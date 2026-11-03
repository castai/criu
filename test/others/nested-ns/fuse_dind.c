/*
 * A nested-ns docker-in-docker topology with a fuse mount, shaped after
 * the coder envbox workspace:
 *
 *   tier0 (this process, the initial user namespace -- the "envbox"
 *   container) forks:
 *
 *     - the fuse server ("sysbox-fs"): it enters the user and mount
 *       namespaces of tier1 and mounts a fuse fs there, serving the
 *       files of a backing directory. It stays a child of tier0, so
 *       it is seized and frozen by the dump exactly like in
 *       production;
 *
 *     - tier1 ("the sysbox tier"): unshares CLONE_NEWUSER and
 *       CLONE_NEWNS (the user namespace the dump enters) and forks
 *       the inner helpers;
 *
 *   the inner helpers ("systemd-journald" and "systemd-resolved"
 *   equivalents) hold an fd on a file of the fuse mount and an
 *   inotify watch on another one, and keep appending to a counter
 *   file on the regular fs.
 *
 * The expected dump behaviour: the fuse fds are closed on restore
 * (their mount is not restored under the nested namespaces), the
 * counter keeps growing after it, and the held fuse fd starts to
 * fail with EBADF.
 *
 * Compile: cc $(pkg-config --cflags fuse3) fuse_dind.c -o fuse_dind \
 *		$(pkg-config --libs fuse3)
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

#define CHECK(x)                                                              \
	do {                                                                  \
		if ((x) < 0) {                                                \
			fprintf(stderr, "%s:%d: %s failed: %s\n", __FILE__,   \
				__LINE__, #x, strerror(errno));               \
			exit(1);                                              \
		}                                                             \
	} while (0)

static const char *backing, *mnt, *counter, *fdstatus;

static int tree_main(char **argv);

/* The fuse passthrough server: runs in the tier1 namespaces. */
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

static int fp_fill(char fpath[4096], const char *path)
{
	if (snprintf(fpath, 4096, "%s%s", backing, path) >= 4096)
		return -ENAMETOOLONG;
	return 0;
}

static int fp_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
	char fpath[4096];
	(void)fi;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	return lstat(fpath, st) < 0 ? -errno : 0;
}

static int fp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
		      struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	char fpath[4096];
	DIR *d;
	struct dirent *de;
	(void)off;
	(void)fi;
	(void)flags;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	d = opendir(fpath);
	if (!d)
		return -errno;
	while ((de = readdir(d)))
		filler(buf, de->d_name, NULL, 0, 0);
	closedir(d);
	return 0;
}

static int fp_open(const char *path, struct fuse_file_info *fi)
{
	char fpath[4096];
	int fd;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	fd = open(fpath, fi->flags);
	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static int fp_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	char fpath[4096];
	int fd;
	int n;
	(void)fi;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = pread(fd, buf, size, off);
	close(fd);
	return n < 0 ? -errno : n;
}

static int fp_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	char fpath[4096];
	int fd;
	int n;
	(void)fi;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	fd = open(fpath, O_WRONLY);
	if (fd < 0)
		return -errno;
	n = pwrite(fd, buf, size, off);
	close(fd);
	return n < 0 ? -errno : n;
}

static int fp_flush(const char *path, struct fuse_file_info *fi)
{
	char fpath[4096];
	int fd;
	(void)fi;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static int fp_truncate(const char *path, off_t off, struct fuse_file_info *fi)
{
	char fpath[4096];
	(void)fi;
	if (fp_fill(fpath, path))
		return -ENAMETOOLONG;
	return truncate(fpath, off) < 0 ? -errno : 0;
}

static struct fuse_operations fp_ops = {
	.getattr = fp_getattr,
	.readdir = fp_readdir,
	.open = fp_open,
	.read = fp_read,
	.write = fp_write,
	.flush = fp_flush,
	.truncate = fp_truncate,
};

static void serve_fuse(pid_t tier1)
{
	char user_ns[64], mnt_ns[64];
	char *argv[6];
	int fd;

	snprintf(user_ns, sizeof(user_ns), "/proc/%d/ns/user", tier1);
	snprintf(mnt_ns, sizeof(mnt_ns), "/proc/%d/ns/mnt", tier1);

	/* A child of tier0 which lives in the namespaces of tier1 */
	fd = open(user_ns, O_RDONLY);
	CHECK(fd);
	CHECK(setns(fd, 0));
	close(fd);
	fd = open(mnt_ns, O_RDONLY);
	CHECK(fd);
	CHECK(setns(fd, 0));
	close(fd);

	argv[0] = (char *)"fuse_dind";
	argv[1] = (char *)"-f";
	argv[2] = (char *)"-s";
	argv[3] = (char *)"-o";
	argv[4] = (char *)"allow_other,default_permissions";
	argv[5] = (char *)mnt;
	/* fuse_main never returns */
	exit(fuse_main(6, argv, &fp_ops, NULL));
}

static void write_map(const char *file, const char *val)
{
	int fd = open(file, O_WRONLY);
	CHECK(fd);
	CHECK(write(fd, val, strlen(val)));
	close(fd);
}

/* The inner helpers: hold a fuse fd + a watch, count in a loop. */
static void helper(const char *hostfile)
{
	char path[4096];
	int fusefd, ifd, wd, n, cfd, epfd;
	struct epoll_event ev;
	unsigned long n_ok = 0;

	snprintf(path, sizeof(path), "%s/%s", mnt, hostfile);
	/* the mount may not be there yet: the server mounts it in parallel */
	for (int i = 0; i < 300; i++) {
		fusefd = open(path, O_RDONLY);
		if (fusefd >= 0)
			break;
		sleep(1);
	}
	CHECK(fusefd);

	ifd = inotify_init();
	CHECK(ifd);
	wd = inotify_add_watch(ifd, path, IN_MODIFY | IN_ATTRIB);
	CHECK(wd);

	/* Like the inner systemd services: the fuse fd is polled */
	epfd = epoll_create1(0);
	CHECK(epfd);
	ev.events = EPOLLIN;
	CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, fusefd, &ev));
	CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev));

	/* The inner container: its own mnt+net ns below the userns-entering
	 * task (substituted at dump): a tmpfs of its own, a socket in its
	 * own net ns, and the fuse fd of the tier1 view. */
	pid_t t2 = fork();
	CHECK(t2);
	if (t2 == 0) {
		char run[64];
		int rfd, sfd;
		struct sockaddr_un su = { .sun_family = AF_UNIX };

		CHECK(unshare(CLONE_NEWNS | CLONE_NEWNET));
		CHECK(mount("none", "/tmp", "tmpfs", 0, NULL));
		snprintf(run, sizeof(run), "/tmp/run-%d", getppid());
		rfd = open(run, O_RDWR | O_CREAT, 0644);
		CHECK(rfd);
		CHECK(dprintf(rfd, "inner container\n") > 0);

		sfd = socket(AF_UNIX, SOCK_STREAM, 0);
		CHECK(sfd);
		snprintf(su.sun_path, sizeof(su.sun_path), "/tmp/sock-%d", getppid());
		unlink(su.sun_path);
		CHECK(bind(sfd, (struct sockaddr *)&su, sizeof(su)));

		/* A daemonized grandchild: its session leader dies and is
		 * reaped, and it is adopted by the subreaper, the way the
		 * daemons of the inner containers of an envbox workspace
		 * are. */
		prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
		{
			pid_t d = fork();

			CHECK(d);
			if (d == 0) {
				CHECK(setsid());
				d = fork();
				CHECK(d);
				if (d > 0)
					_exit(0);

				/* the grandchild: the session of the dead leader */
				for (;;)
					sleep(1);
				_exit(0); /* not reached */
			}
			waitpid(d, NULL, 0);
		}

		for (;;) {
			char b2[64];
			int e2 = 0;

			/* The fuse fd is inherited from the parent helper */
			if (read(fusefd, b2, sizeof(b2)) < 0)
				e2 = errno;
			(void)e2;
			sleep(1);
		}
		_exit(0); /* not reached */
	}

	for (;;) {
		char buf[64];
		int err = 0;

		/* Touch the fuse fd to learn its fate */
		n = read(fusefd, buf, sizeof(buf));
		if (n < 0)
			err = errno;

		cfd = open(counter, O_WRONLY | O_APPEND | O_CREAT, 0644);
		CHECK(cfd);
		n = dprintf(cfd, "tick %lu\n", ++n_ok);
		CHECK(n > 0 ? 0 : -1);
		close(cfd);

		cfd = open(fdstatus, O_WRONLY | O_TRUNC | O_CREAT, 0644);
		CHECK(cfd);
		dprintf(cfd, "%d\n", err);
		close(cfd);

		sleep(1);
	}
}

int main(int argc, char **argv)
{
	int syncpipe[2];
	pid_t tier1, srv;
	char buf[8];
	int n;

	if (argc == 6) {
		/* Like a container runtime creates a pid namespace for a
		 * container: the whole tree runs in one, with its init as
		 * the session leader of its own, and the dump and the
		 * restore are run from the outside of it (see fuse-dind.sh,
		 * the PIDFILE is written with the pid of the init at the
		 * level of the launcher). */
		pid_t init;
		FILE *f;

		CHECK(unshare(CLONE_NEWPID));
		init = fork();
		CHECK(init);
		if (init == 0) {
			if (setsid() < 0 && errno != EPERM)
				CHECK(-1);
			return tree_main(argv);
		}
		f = fopen(argv[5], "w");
		CHECK(f ? 0 : -1);
		fprintf(f, "%d\n", (int)init);
		fclose(f);
		for (;;) /* the runtime launcher */
			pause();
	}

	if (argc != 5) {
		fprintf(stderr, "usage: %s BACKING MNT COUNTER FDSTATUS [PIDFILE]\n", argv[0]);
		return 1;
	}
	return tree_main(argv);
}

static int tree_main(char **argv)
{
	int syncpipe[2];
	pid_t tier1, srv;
	char buf[8];
	int n;

	/* Like a container init (runc unshares one for it): the root
	 * task of the dump lives in a mount namespace of its own, not
	 * in the one of whoever runs the dump. */
	CHECK(unshare(CLONE_NEWNS));
	CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));

	/* Like a container runtime mounts for a container: the tree sees
	 * the pids of its own pid namespace in /proc, not the ones of the
	 * level the dump runs at. */
	CHECK(mount("proc", "/proc", "proc", 0, NULL));

	backing = argv[1];
	mnt = argv[2];
	counter = argv[3];
	fdstatus = argv[4];

	CHECK(pipe(syncpipe));

	/* tier1: the nested user+mount namespaces */
	tier1 = fork();
	CHECK(tier1);
	if (tier1 == 0) {
		CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS));
		write_map("/proc/self/setgroups", "deny");
		write_map("/proc/self/uid_map", "0 0 1\n");
		write_map("/proc/self/gid_map", "0 0 1\n");
		CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
		CHECK(mkdir(mnt, 0755) < 0 && errno != EEXIST ? -1 : 0);

		/* tell tier0 where to find our namespaces */
		n = sprintf(buf, "%d", 1);
		CHECK(write(syncpipe[1], buf, n));
		close(syncpipe[0]);
		close(syncpipe[1]);

		helper("hostname"); /* the journald one */
		_exit(0); /* not reached */
	}
	close(syncpipe[1]);
	n = read(syncpipe[0], buf, sizeof(buf) - 1);
	CHECK(n);
	buf[n] = 0;
	close(syncpipe[0]);

	/* the fuse server: a child of tier0 in the namespaces of tier1 */
	srv = fork();
	CHECK(srv);
	if (srv == 0)
		serve_fuse(tier1);

	/* tier0 loops: the dump root */
	for (;;)
		sleep(1000);
	return 0;
}
