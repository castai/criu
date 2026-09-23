#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sched.h>
#include <grp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <net/if.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check C/R of a process in a nested user namespace";
const char *test_author = "CAST AI";

/*
 * The test emulates a docker-in-docker (dind) workload:
 *
 *   - the root task lives in its own user namespace (A), like a
 *     container with a user namespace mapping,
 *   - the root task starts a child which enters a user namespace (B)
 *     nested inside A, like a container spawned by a dind daemon:
 *     the child creates the user, uts, mount and network namespaces
 *     of B, and a pid one, whose init task (the worker) is forked
 *     into it,
 *   - the root task also starts an entering task, which joins the
 *     namespaces of B with setns() and is re-parented under the root
 *     one (a subreaper) after its forking task exits, like a docker
 *     exec-ed process of the container.
 *
 * The child verifies its ids, the id mappings and the nested userns
 * relationship are preserved by C/R; the worker, the init one of the
 * nested pid namespace, checks its pid in it; the entering task checks
 * it is a member of the namespaces of B with the pid it had in them.
 */

/*
 * The content of a tmpfs of a nested user namespace with hard-link
 * remapped files is not dumped (the bind mount of the remap tree of
 * the dumping one hits the kernel mount locks of the nested
 * namespace): the files of the test live on the regular filesystem,
 * the tmpfs of the child stays empty and is restored as a fresh one.
 */
/*
 * The namespace file descriptors of B, opened by the child living in
 * it (the ones of its own namespaces and of the worker) and passed to
 * the root one over a socketpair: the entering forking task, which
 * lives in the parent user namespace, may not be allowed to open the
 * ones of the tasks of B itself.
 */
static int join_ns_fd[5];
static int ns_sock[2];

#define NSFD_USER 0
#define NSFD_UTS  1
#define NSFD_MNT  2
#define NSFD_NET  3
#define NSFD_PID  4

#define MARKER_FILE "userns_nested.dat"
#define MARKER_DATA "userns_nested"
#define WORKER_FILE "nested-worker-file"
#define WORKER_DATA "nested-worker-data"
#define HOSTNAME_B  "nested-uts-host"
#define BIND_SRC    "nested-bind-src"
#define BIND_DATA   "nested-bind-data"
#define BIND_TARGET "/tmp/nested-bind-target"
#define OWNED_FILE  "/tmp/nested-owned"

enum {
	TEST_FORKED,
	TEST_UNSHARED,
	TEST_MAPPED,
	TEST_READY,
	TEST_CHECK,
	TEST_EXIT,

	WORKER_FORKED,
	WORKER_READY,
	WORKER_CHECK,
	WORKER_EXIT,

	ENTERER_FORKED,
	ENTERER_READY,
	ENTERER_CHECK,
	ENTERER_EXIT,
};

struct id_extent {
	unsigned int first;
	unsigned int lower_first;
	unsigned int count;
};

/* clang-format off */
struct shared {
	futex_t fstate;
	futex_t worker_fstate;
	futex_t enterer_fstate;
	int child_ret;
	int worker_ret;
	int enterer_ret;
	pid_t worker_pid; /* as seen from the root pid namespace */
	struct id_extent uid_ext;
	struct id_extent gid_ext;
	char uid_map_before[256];
	char gid_map_before[256];
	char parent_ns_before[64];
	char child_ns_after[64];
	/* The working directory of the test, for the tasks joining B's mount namespace */
	char cwd[PATH_MAX];
	pid_t enterer_pid_in_b; /* as seen from the pid namespace of B */
} *sh;
/* clang-format on */

static int read_file_text(const char *path, char *buf, int size)
{
	int fd, len;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	len = read(fd, buf, size - 1);
	close(fd);
	if (len < 0) {
		pr_perror("Can't read %s", path);
		return -1;
	}

	buf[len] = '\0';
	return 0;
}

static int parse_map_extents(const char *path, struct id_extent *exts, int max)
{
	char buf[4096];
	char *line, *save;
	int nr = 0;

	if (read_file_text(path, buf, sizeof(buf)))
		return -1;

	for (line = strtok_r(buf, "\n", &save); line && nr < max;
	     line = strtok_r(NULL, "\n", &save)) {
		unsigned int first, lower_first, count;

		if (sscanf(line, "%u %u %u", &first, &lower_first, &count) != 3) {
			pr_err("Bad map line '%s' in %s\n", line, path);
			return -1;
		}

		exts[nr].first = first;
		exts[nr].lower_first = lower_first;
		exts[nr].count = count;
		nr++;
	}

	return nr;
}

/*
 * Pick an id block of the root task's user namespace to be mapped
 * into the nested one. Prefer a block which is not mapped from zero,
 * like the sub-id blocks docker uses for user namespace remapping.
 */
static int pick_extent(const char *path, struct id_extent *ext)
{
	struct id_extent exts[32];
	int nr, i;

	nr = parse_map_extents(path, exts, ARRAY_SIZE(exts));
	if (nr < 0)
		return -1;

	if (nr == 0) {
		pr_err("No extents in %s\n", path);
		return -1;
	}

	*ext = exts[0];
	for (i = 0; i < nr; i++) {
		if (exts[i].first) {
			*ext = exts[i];
			break;
		}
	}

	return 0;
}

static int write_map_file(int pid, const char *name, const char *value)
{
	char path[64];
	int fd, len = strlen(value);

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (write(fd, value, len) != len) {
		pr_perror("Can't write %s", path);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int read_task_ns_user(int pid, char *buf, int size)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);

	if (readlink(path, buf, size - 1) < 0) {
		pr_perror("Can't readlink %s", path);
		return -1;
	}

	return 0;
}

static int check_task_in_nested_userns(int pid)
{
	char parent_ns[64], child_ns[64];
	if (read_task_ns_user(getpid(), parent_ns, sizeof(parent_ns)))
		return -1;

	if (read_task_ns_user(pid, child_ns, sizeof(child_ns)))
		return -1;

	if (!strcmp(parent_ns, child_ns)) {
		pr_err("Task %d is in the same user namespace as the root task\n", pid);
		return -1;
	}

	return 0;
}

static int loopback_is_up(void)
{
	struct ifreq ifr;
	int sfd, up;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd < 0) {
		pr_perror("Can't open socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(sfd, SIOCGIFFLAGS, &ifr)) {
		pr_perror("Can't get lo flags");
		close(sfd);
		return -1;
	}
	close(sfd);

	up = !!(ifr.ifr_flags & IFF_UP);
	return up;
}

static int bring_loopback_up(void)
{
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sfd < 0) {
		pr_perror("Can't open socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	ifr.ifr_flags = IFF_UP | IFF_RUNNING;
	if (ioctl(sfd, SIOCSIFFLAGS, &ifr)) {
		pr_perror("Can't bring lo up");
		close(sfd);
		return -1;
	}
	close(sfd);

	return 0;
}

static int hostname_is_ours(void)
{
	struct utsname ubuf;

	if (uname(&ubuf)) {
		pr_perror("Can't uname");
		return 0;
	}

	return !strncmp(ubuf.nodename, HOSTNAME_B, sizeof(HOSTNAME_B) - 1);
}

/*
 * The checks of the namespaces of B, run by the tasks living in them
 * after C/R: the ids, the hostname, the loopback of the network one,
 * the file of the tmpfs mounted in the mount one, and the marker one
 * held with an open fd since before C/R.
 */
static int check_nested_ns_state(int marker_fd)
{
	char buf[256];
	struct stat st2, st3, st4;
	int bfd;

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids in the nested userns: uid=%d gid=%d\n", getuid(), getgid());
		return -1;
	}

	if (stat(OWNED_FILE, &st4)) {
		pr_perror("Can't stat %s after C/R", OWNED_FILE);
		return -1;
	}
	if (st4.st_uid != 0 || st4.st_gid != 0) {
		pr_err("%s is owned by %d:%d after C/R, not by our root\n", OWNED_FILE, st4.st_uid, st4.st_gid);
		return -1;
	}

	bfd = open(BIND_TARGET, O_RDONLY);
	if (bfd < 0) {
		pr_perror("Can't open %s after C/R", BIND_TARGET);
		return -1;
	}
	if (read(bfd, buf, sizeof(BIND_DATA)) != sizeof(BIND_DATA) || strncmp(buf, BIND_DATA, sizeof(BIND_DATA))) {
		pr_err("Bad content of the bind mount %s after C/R\n", BIND_TARGET);
		close(bfd);
		return -1;
	}
	close(bfd);

	if (!hostname_is_ours()) {
		pr_err("Hostname lost after C/R\n");
		return -1;
	}

	if (!loopback_is_up()) {
		pr_err("lo is down after C/R\n");
		return -1;
	}

	if (stat("/", &st2) || stat("/tmp", &st3)) {
		pr_perror("Can't stat / and /tmp");
		return -1;
	}

	if (st2.st_dev == st3.st_dev) {
		pr_err("/tmp is not a separate mount after C/R\n");
		return -1;
	}

	if (lseek(marker_fd, 0, SEEK_SET) < 0) {
		pr_perror("Can't lseek the marker file");
		return -1;
	}

	if (read(marker_fd, buf, sizeof(MARKER_DATA)) != sizeof(MARKER_DATA) ||
	    strncmp(buf, MARKER_DATA, sizeof(MARKER_DATA))) {
		pr_err("Bad marker file content after C/R\n");
		return -1;
	}

	return 0;
}

/*
 * The init task of the pid namespace of B, forked into it by the
 * child: the inner container workload. It is restored as the init one
 * of the namespace as well, tracked by its pid in the one of the
 * restoring criu, and it collects the tasks of the namespace below it
 * (the entering one, restored as its child).
 */
static int worker_task(int marker_fd)
{
	int fd, status;
	pid_t w;

	if (getpid() != 1) {
		pr_err("The worker is not the init of the pid namespace: pid %d\n", getpid());
		return -1;
	}

	fd = open(WORKER_FILE, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't open %s", WORKER_FILE);
		return -1;
	}
	if (write(fd, WORKER_DATA, sizeof(WORKER_DATA)) != sizeof(WORKER_DATA)) {
		pr_perror("Can't write %s", WORKER_FILE);
		close(fd);
		return -1;
	}
	close(fd);

	futex_set_and_wake(&sh->worker_fstate, WORKER_READY);
	futex_wait_until(&sh->worker_fstate, WORKER_CHECK);

	if (getpid() != 1) {
		pr_err("The worker is not the init of the pid namespace after C/R: pid %d\n", getpid());
		return -1;
	}

	if (check_nested_ns_state(marker_fd)) {
		sh->worker_ret = -1;
	} else {
		char buf[64];
		int rn;

		rn = open(WORKER_FILE, O_RDONLY);
		if (rn < 0) {
			pr_perror("Can't open %s after C/R", WORKER_FILE);
			sh->worker_ret = -1;
		} else {
			int n = read(rn, buf, sizeof(buf) - 1);

			close(rn);
			if (n != sizeof(WORKER_DATA) || strncmp(buf, WORKER_DATA, sizeof(WORKER_DATA))) {
				pr_err("Bad %s content after C/R\n", WORKER_FILE);
				sh->worker_ret = -1;
			}
		}
	}

	if (close(marker_fd))
		pr_perror("Can't close the marker file");

	/*
	 * The entering task is restored as our child (it is re-parented
	 * under us at restore): collect it and take its exit code into
	 * ours. The pre-C/R one is not our child (the root task, a
	 * subreaper, holds it), so a miss is not an error.
	 */
	while ((w = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status) && !WEXITSTATUS(status))
			continue;
		pr_err("A task of the pid namespace exited with status %d\n", status);
		sh->worker_ret = -1;
	}

	if (sh->worker_ret) {
		futex_set_and_wake(&sh->worker_fstate, WORKER_EXIT);
		return -1;
	}

	futex_set_and_wake(&sh->worker_fstate, WORKER_EXIT);
	return 0;
}

static int nested_child(void)
{
	char buf[256];
	int fd, status;
	pid_t worker;

	if (setgroups(0, NULL) && errno != EPERM) {
		pr_perror("Can't drop supplementary groups");
		goto err;
	}

	/*
	 * Drop to a sub-id of the root task's user namespace, like
	 * runc does before creating a remapped container, so that
	 * the nested user namespace maps us back to uid 0.
	 */
	if (setresgid(sh->gid_ext.first, sh->gid_ext.first, sh->gid_ext.first)) {
		pr_perror("Can't set gid %u", sh->gid_ext.first);
		goto err;
	}

	if (setresuid(sh->uid_ext.first, sh->uid_ext.first, sh->uid_ext.first)) {
		pr_perror("Can't set uid %u", sh->uid_ext.first);
		goto err;
	}

	/*
	 * The id switch clears the dumpable flag, which the tasks forked
	 * below inherit: their /proc/<pid>/ns directories would then be
	 * owned by the root of the outer user namespace, not by us, and
	 * the namespace files of the worker could not be opened. Set it
	 * back, like a container runtime does after switching its ids.
	 */
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) {
		pr_perror("Can't set the dumpable flag");
		goto err;
	}

	if (unshare(CLONE_NEWUSER)) {
		pr_perror("Can't unshare user namespace");
		goto err;
	}

	/* our own uts namespace, like an inner container has */
	if (unshare(CLONE_NEWUTS)) {
		pr_perror("Can't unshare uts namespace");
		goto err;
	}

	if (sethostname(HOSTNAME_B, sizeof(HOSTNAME_B) - 1)) {
		pr_perror("Can't set hostname");
		goto err;
	}

	/* our own mount namespace, filled in after the maps are set */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Can't unshare mnt namespace");
		goto err;
	}

	/* our own network namespace with the loopback up */
	if (unshare(CLONE_NEWNET)) {
		pr_perror("Can't unshare net namespace");
		goto err;
	}

	if (bring_loopback_up())
		goto err;

	futex_set_and_wake(&sh->fstate, TEST_UNSHARED);
	futex_wait_until(&sh->fstate, TEST_MAPPED);

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids in the nested userns: uid=%d gid=%d\n", getuid(), getgid());
		goto err;
	}

	/*
	 * Mount our own tmpfs on /tmp, like an inner container rootfs.
	 * Our ids are mapped now, so the files we create in it are owned
	 * by our uid in the nested user namespace.
	 */
	if (mount(NULL, "/tmp", "tmpfs", 0, "size=1m")) {
		pr_perror("Can't mount tmpfs on /tmp");
		goto err;
	}

	/* Stash the mappings to compare them after C/R */
	if (read_file_text("/proc/self/uid_map", sh->uid_map_before, sizeof(sh->uid_map_before)))
		goto err;

	if (read_file_text("/proc/self/gid_map", sh->gid_map_before, sizeof(sh->gid_map_before)))
		goto err;

	fd = open(MARKER_FILE, O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd < 0) {
		pr_perror("Can't open %s", MARKER_FILE);
		goto err;
	}

	if (write(fd, MARKER_DATA, sizeof(MARKER_DATA)) != sizeof(MARKER_DATA)) {
		pr_perror("Can't write %s", MARKER_FILE);
		close(fd);
		goto err;
	}

	/*
	 * A file of our tmpfs owned by our root: its owner is mapped
	 * through our id maps at restore (the archive holds the ids of
	 * the outer user namespace).
	 */
	{
		int ofd = open(OWNED_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);

		if (ofd < 0) {
			pr_perror("Can't create %s", OWNED_FILE);
			close(fd);
			goto err;
		}
		close(ofd);
	}

	/*
	 * A bind mount of a file of the parent's filesystem into our
	 * tmpfs, like the /etc/hosts of an inner container: its source
	 * is resolved through the parent's mount tree at restore.
	 */
	{
		int bfd = open(BIND_SRC, O_CREAT | O_WRONLY | O_TRUNC, 0644);

		if (bfd < 0 || write(bfd, BIND_DATA, sizeof(BIND_DATA)) != sizeof(BIND_DATA)) {
			pr_perror("Can't create %s", BIND_SRC);
			close(fd);
			goto err;
		}
		close(bfd);

		bfd = open(BIND_TARGET, O_CREAT | O_WRONLY, 0644);
		if (bfd < 0) {
			pr_perror("Can't create %s", BIND_TARGET);
			close(fd);
			goto err;
		}
		close(bfd);

		if (mount(BIND_SRC, BIND_TARGET, NULL, MS_BIND, NULL)) {
			pr_perror("Can't bind %s to %s", BIND_SRC, BIND_TARGET);
			close(fd);
			goto err;
		}
	}

	/*
	 * Our own pid namespace, like an inner container has: we stay
	 * outside of it (like the runtime task which has created the
	 * container), the tasks we fork below it live in it.
	 */
	if (unshare(CLONE_NEWPID)) {
		pr_perror("Can't unshare pid namespace");
		close(fd);
		goto err;
	}

	worker = fork();
	if (worker < 0) {
		pr_perror("Can't fork the worker");
		close(fd);
		goto err;
	}
	if (worker == 0)
		_exit(worker_task(fd) ? 1 : 0);

	/* The pid of the worker in the root pid namespace, for setns() */
	sh->worker_pid = worker;

	/*
	 * Pass the namespaces of ours to the root task: our own ones and
	 * the pid namespace of the worker, the one we have created and it
	 * lives in. The entering forking task of the root one may not be
	 * allowed to open the ones of our tasks.
	 */
	{
		int ns_fds[5];
		struct msghdr msg = {};
		int dummy = 0;
		struct iovec iov = { &dummy, sizeof(dummy) };
		char cmsgbuf[CMSG_SPACE(sizeof(ns_fds))];
		struct cmsghdr *cmsg;
		char path[64];
		int i;

		ns_fds[NSFD_USER] = open("/proc/self/ns/user", O_RDONLY);
		ns_fds[NSFD_UTS] = open("/proc/self/ns/uts", O_RDONLY);
		ns_fds[NSFD_MNT] = open("/proc/self/ns/mnt", O_RDONLY);
		ns_fds[NSFD_NET] = open("/proc/self/ns/net", O_RDONLY);
		snprintf(path, sizeof(path), "/proc/%d/ns/pid", worker);
		ns_fds[NSFD_PID] = open(path, O_RDONLY);

		for (i = 0; i < 5; i++) {
			if (ns_fds[i] < 0) {
				pr_perror("Can't open the namespace file %d", i);
				goto err;
			}
		}

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(ns_fds));
		memcpy(CMSG_DATA(cmsg), ns_fds, sizeof(ns_fds));

		if (sendmsg(ns_sock[1], &msg, 0) != sizeof(dummy)) {
			pr_perror("Can't send the namespace file descriptors");
			goto err;
		}
		close(ns_sock[1]);
	}

	futex_set_and_wake(&sh->fstate, TEST_READY);
	futex_wait_until(&sh->fstate, TEST_CHECK);

	/* Check that C/R kept the nested user namespace intact */
	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids after C/R: uid=%d gid=%d\n", getuid(), getgid());
		goto err_collect;
	}

	if (readlink("/proc/self/ns/user", sh->child_ns_after, sizeof(sh->child_ns_after) - 1) < 0) {
		pr_perror("Can't readlink /proc/self/ns/user");
		goto err_collect;
	}

	if (read_file_text("/proc/self/uid_map", buf, sizeof(buf)))
		goto err_collect;

	if (strcmp(buf, sh->uid_map_before)) {
		pr_err("uid_map changed after C/R: '%s' != '%s'\n", buf, sh->uid_map_before);
		goto err_collect;
	}

	if (read_file_text("/proc/self/gid_map", buf, sizeof(buf)))
		goto err_collect;

	if (strcmp(buf, sh->gid_map_before)) {
		pr_err("gid_map changed after C/R: '%s' != '%s'\n", buf, sh->gid_map_before);
		goto err_collect;
	}

	/* Let the worker check its own state and exit */
	futex_set_and_wake(&sh->worker_fstate, WORKER_CHECK);

	/*
	 * Collect the worker and take its verdict into ours. It is our
	 * only child, and it is waited for by any pid: its pid in our
	 * pid namespace is not restored, as we live in a nested user
	 * namespace without the capabilities to set it there (the init
	 * of an inner container is forked by a runtime task of the
	 * outer user namespace, which has them).
	 */
	while (waitpid(-1, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("The worker exited with status %d\n", status);
		goto err_collect;
	}

	if (sh->worker_ret) {
		fail("The worker of the nested pid namespace failed");
		goto err_collect;
	}

	close(fd);
	futex_set_and_wake(&sh->fstate, TEST_EXIT);
	return 0;

err_collect:
	kill(worker, SIGKILL);
	waitpid(worker, NULL, 0);
err:
	sh->child_ret = -1;
	futex_set_and_wake(&sh->fstate, TEST_EXIT);
	return -1;
}

/*
 * The forking task of the entering one: it joins the namespaces of B
 * and forks the entering task into them (a setns() into a pid
 * namespace moves the children of the caller into it), then exits, so
 * the entering task is re-parented under the root one (a subreaper),
 * like the runtime task of a docker exec does.
 */
static int enterer_task(void);

static int enterer_mid(void)
{
	pid_t enterer;
	int i;

	/* The user namespace of B first, then the ones owned by it */
	for (i = 0; i < 5; i++) {
		static const int cflags[5] = { CLONE_NEWUSER, CLONE_NEWUTS, CLONE_NEWNS,
					       CLONE_NEWNET, CLONE_NEWPID };

		if (setns(join_ns_fd[i], cflags[i])) {
			pr_perror("Can't join the namespace fd %d", i);
			return -1;
		}
	}

	/*
	 * Our ids are the ones of A, which are not mapped in B: become
	 * the root of B, like the runtime task of a docker exec does.
	 */
	if (setgroups(0, NULL) && errno != EPERM) {
		pr_perror("Can't drop the groups in B");
		return -1;
	}
	if (setresgid(0, 0, 0) || setresuid(0, 0, 0)) {
		pr_perror("Can't become the root of B");
		return -1;
	}

	/*
	 * Joining a mount namespace puts us at its root: get back to the
	 * directory of the test, where the marker file is.
	 */
	if (chdir(sh->cwd)) {
		pr_perror("Can't chdir to %s in the mount namespace of B", sh->cwd);
		return -1;
	}

	enterer = fork();
	if (enterer < 0) {
		pr_perror("Can't fork the entering task");
		return -1;
	}
	if (enterer == 0)
		_exit(enterer_task());

	return 0;
}

static int enterer_task(void)
{
	int fd;

	/* The pid of ours in the pid namespace of B, to compare after C/R */
	sh->enterer_pid_in_b = getpid();

	fd = open(MARKER_FILE, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", MARKER_FILE);
		goto err;
	}

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids of the entering task: uid=%d gid=%d\n", getuid(), getgid());
		goto err;
	}

	if (!hostname_is_ours()) {
		pr_err("The entering task does not see the hostname of B\n");
		goto err;
	}

	if (!loopback_is_up()) {
		pr_err("lo is down in the network namespace of B\n");
		goto err;
	}

	/* Our own process group, known by our pid in the pid namespace of B */
	if (setpgid(0, 0)) {
		pr_perror("Can't set the process group of the entering task");
		goto err;
	}

	futex_set_and_wake(&sh->enterer_fstate, ENTERER_READY);
	futex_wait_until(&sh->enterer_fstate, ENTERER_CHECK);

	if (getpid() != sh->enterer_pid_in_b) {
		pr_err("The pid of the entering task in the pid namespace of B changed: %d != %d\n",
		       getpid(), sh->enterer_pid_in_b);
		goto err;
	}

	if (getpgrp() != getpid()) {
		pr_err("The process group of the entering task changed: %d != %d\n", getpgrp(), getpid());
		goto err;
	}

	if (check_nested_ns_state(fd))
		sh->enterer_ret = -1;

	if (sh->enterer_ret) {
		futex_set_and_wake(&sh->enterer_fstate, ENTERER_EXIT);
		close(fd);
		return -1;
	}

	futex_set_and_wake(&sh->enterer_fstate, ENTERER_EXIT);
	close(fd);
	return 0;
err:
	sh->enterer_ret = -1;
	futex_set_and_wake(&sh->enterer_fstate, ENTERER_EXIT);
	return -1;
}

int main(int argc, char **argv)
{
	char buf[256];
	int pid, status;
	int ret = 0, child_reaped = 0;

	sh = mmap(NULL, sizeof(struct shared), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Can't map shared region");
		exit(1);
	}

	futex_set(&sh->fstate, TEST_FORKED);
	futex_set(&sh->worker_fstate, WORKER_FORKED);
	futex_set(&sh->enterer_fstate, ENTERER_FORKED);

	test_init(argc, argv);

	if (!getcwd(sh->cwd, sizeof(sh->cwd))) {
		pr_perror("Can't get the working directory");
		exit(1);
	}

	/*
	 * The entering task is re-parented under us when its forking one
	 * exits: we are the nearest subreaper of it, like the runtime
	 * task of a docker exec is the one of the exec-ed process.
	 */
	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
		pr_perror("Can't set the child subreaper");
		exit(1);
	}

	/* Pick sub-id blocks of our user namespace for the nested one */
	if (pick_extent("/proc/self/uid_map", &sh->uid_ext)) {
		fail("Can't pick a uid extent");
		exit(1);
	}

	if (pick_extent("/proc/self/gid_map", &sh->gid_ext)) {
		fail("Can't pick a gid extent");
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ns_sock)) {
		pr_perror("Can't create the namespace socketpair");
		exit(1);
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		exit(1);
	} else if (pid == 0) {
		close(ns_sock[0]);
		exit(nested_child() ? 1 : 0);
	}
	close(ns_sock[1]);

	futex_wait_while_lt(&sh->fstate, TEST_UNSHARED);

	/*
	 * We are in the parent user namespace of the new one, so
	 * we are allowed to fill in its id mappings, like a dind
	 * daemon does for the containers it spawns.
	 */
	if (write_map_file(pid, "setgroups", "deny")) {
		fail("Can't deny setgroups");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->uid_ext.first, sh->uid_ext.count);
	if (write_map_file(pid, "uid_map", buf)) {
		fail("Can't write uid_map");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->gid_ext.first, sh->gid_ext.count);
	if (write_map_file(pid, "gid_map", buf)) {
		fail("Can't write gid_map");
		exit(1);
	}

	futex_set_and_wake(&sh->fstate, TEST_MAPPED);
	futex_wait_while_lt(&sh->fstate, TEST_READY);

	/* Take the namespaces of B over from the child */
	{
		struct msghdr msg = {};
		int dummy;
		struct iovec iov = { &dummy, sizeof(dummy) };
		char cmsgbuf[CMSG_SPACE(sizeof(join_ns_fd))];
		struct cmsghdr *cmsg;

		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		if (recvmsg(ns_sock[0], &msg, 0) < 0) {
			fail("Can't receive the namespace file descriptors");
			exit(1);
		}
		cmsg = CMSG_FIRSTHDR(&msg);
		if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(join_ns_fd))) {
			fail("Bad namespace file descriptors message");
			exit(1);
		}
		memcpy(join_ns_fd, CMSG_DATA(cmsg), sizeof(join_ns_fd));
		close(ns_sock[0]);
	}

	/* Check we really have a nested user namespace before C/R */
	if (check_task_in_nested_userns(pid)) {
		fail("No nested user namespace before C/R");
		exit(1);
	}

	/* Stash our user namespace link to compare with the child's one */
	if (readlink("/proc/self/ns/user", sh->parent_ns_before, sizeof(sh->parent_ns_before) - 1) < 0) {
		fail("Can't readlink /proc/self/ns/user");
		exit(1);
	}

	/*
	 * Start the entering task: it joins the namespaces of B and is
	 * re-parented under us when its forking task exits. Its pre-C/R
	 * parent is us, while at restore it is forked by the task of B
	 * (the worker one), which inherits the namespaces to it.
	 */
	{
		int mid = fork();

		if (mid < 0) {
			pr_perror("Can't fork the entering forking task");
			exit(1);
		}
		if (mid == 0)
			exit(enterer_mid() ? 1 : 0);

		/* The forking task exits right after forking the entering one */
		while (waitpid(mid, &status, 0) < 0 && errno == EINTR)
			;
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("The entering forking task failed");
			exit(1);
		}
	}

	futex_wait_while_lt(&sh->enterer_fstate, ENTERER_READY);
	futex_wait_while_lt(&sh->worker_fstate, WORKER_READY);

	test_daemon();
	test_waitsig();

	/*
	 * The child has stashed the link of its user namespace, as
	 * reading the ns files of another task of a task in a nested
	 * user namespace may be restricted. Check that it is not
	 * ours, i.e. that the child is still in a nested one.
	 */
	if (!strcmp(sh->child_ns_after, sh->parent_ns_before)) {
		fail("The child is in our user namespace after C/R");
		ret = 1;
	}

	/*
	 * The entering task is collected by the worker after C/R (it is
	 * re-parented under it at restore). Without C/R it is still
	 * ours: reap it, or the init of the pid namespace (the worker)
	 * can not exit while a zombie of its namespace is unreaped.
	 */
	futex_set_and_wake(&sh->fstate, TEST_CHECK);
	futex_set_and_wake(&sh->enterer_fstate, ENTERER_CHECK);

	/*
	 * Without C/R the first child to exit is the entering one: the
	 * child (and the worker) can not finish before it is reaped.
	 * With C/R it is the child itself, whose status is kept.
	 */
	{
		int st;
		pid_t w;

		while ((w = waitpid(-1, &st, 0)) < 0 && errno == EINTR)
			;
		test_msg("Reaped the child %d (status %d, the nested one is %d)\n", w, st, pid);
		if (w == pid) {
			status = st;
			child_reaped = 1;
		}
	}

	/*
	 * Give the child (and the worker and the entering tasks below it)
	 * some time to check their state after C/R and exit, then collect
	 * the child. Its exit code tells whether the checks passed.
	 */
	futex_wait_until(&sh->fstate, TEST_EXIT);
	test_msg("The nested child is done\n");

	if (!child_reaped)
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("The child exited with status %d\n", status);
		ret = 1;
	}

	if (ret)
		return 1;

	if (sh->child_ret) {
		fail("Nested user namespace child failed");
		return 1;
	}

	if (sh->enterer_ret) {
		fail("The task which entered the nested user namespace failed");
		return 1;
	}

	unlink(MARKER_FILE);
	unlink(BIND_SRC);
	pass();
	return 0;
}
