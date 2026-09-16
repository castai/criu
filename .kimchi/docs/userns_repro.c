#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <linux/sched.h>

#define PROC_A "/tmp/procA.repro"
#define READY "/tmp/c1maps.ready"

static int write_file(const char *path, const char *value)
{
	int fd, len = strlen(value);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (write(fd, value, len) != len) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int write_map_at(const char *procdir, pid_t pid, const char *name, const char *value)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%d/%s", procdir, pid, name);
	return write_file(path, value);
}

static int write_map_at_fd(int dfd, pid_t pid, const char *name, const char *value)
{
	char path[256];
	int fd, len = strlen(value);

	snprintf(path, sizeof(path), "%d/%s", pid, name);
	fd = openat(dfd, path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "openat %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (write(fd, value, len) != len) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int proc_fd = -1;

static int child_fn(void *arg)
{
	pid_t c2;
	int sync2[2];
	char c;

	(void)arg;

	/*
	 * We are C1: born in userns A + new mntns + new pidns (owned
	 * by A, as CLONE_NEWUSER is processed first), like the CRIU
	 * root task.
	 */

	/* wait for P to write A's maps */
	{
		int i;

		for (i = 0; i < 100; i++) {
			if (access(READY, F_OK) == 0)
				break;
			usleep(100000);
		}
		if (i == 100) {
			fprintf(stderr, "C1: no maps ready\n");
			_exit(1);
		}
	}

	if (setgroups(0, NULL))
		;
	if (setresgid(0, 0, 0) || setresuid(0, 0, 0)) {
		perror("C1 setresid");
		_exit(1);
	}

	/*
	 * Mount a procfs in A, like the restored root task does.
	 */
	if (mkdir(PROC_A, 0777) && errno != EEXIST) {
		perror("mkdir procA");
		_exit(1);
	}
	if (mount("proc", PROC_A, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
		perror("mount procA");
		_exit(1);
	}

	/* C1 forks C2 in a new userns B nested in A, via clone3 with
	 * set_tid, like CRIU creates a task in a new user namespace */
	if (pipe(sync2)) {
		perror("pipe");
		_exit(1);
	}

	{
		struct {
			uint64_t flags;
			uint64_t pidfd;
			uint64_t child_tid;
			uint64_t parent_tid;
			uint64_t exit_signal;
			uint64_t stack;
			uint64_t stack_size;
			uint64_t tls;
			uint64_t set_tid;
			uint64_t set_tid_size;
			uint64_t cgroup;
		} c_args = {};
		int ctid = 2;
		int cret;

		c_args.flags = CLONE_NEWUSER;
		c_args.exit_signal = SIGCHLD;
		c_args.set_tid = (uint64_t)&ctid;
		c_args.set_tid_size = 1;

		cret = syscall(__NR_clone3, &c_args, sizeof(c_args));
		if (cret < 0) {
			perror("clone3 C2");
			_exit(1);
		}
		if (cret == 0) {
			/* C2: in the new userns B */
			if (write(sync2[1], "R", 1) != 1)
				_exit(1);

			sleep(15);
			printf("C2: uid=%d gid=%d\n", getuid(), getgid());
			fflush(stdout);
			_exit(0);
		}
		c2 = cret;
	}

	/* wait for C2 to unshare B */
	if (read(sync2[0], &c, 1) != 1)
		_exit(1);

	printf("C1: uid=%d, c2 (in our pidns) = %d\n", getuid(), c2);
	fflush(stdout);

	/* tell P the pid of C2 in our pid namespace */
	{
		char buf[32];
		int fd;

		snprintf(buf, sizeof(buf), "%d", c2);
		fd = open("/tmp/c2pid", O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (write(fd, buf, strlen(buf)) != (int)strlen(buf))
			perror("write c2pid");
		close(fd);
	}

	waitpid(c2, NULL, 0);
	printf("C1: done\n");
	fflush(stdout);
	_exit(0);
}

static char child_stack[64 * 1024];

int main(void)
{
	pid_t c1, c2g = 0;
	int status;
	char c;
	char buf[64];
	int fd, len, i;

	/* P (container root) clones C1 like CRIU forks the root task */
	proc_fd = open("/proc", O_DIRECTORY | O_RDONLY);
	if (proc_fd < 0) {
		perror("open /proc");
		exit(1);
	}
	c1 = clone(child_fn, child_stack + sizeof(child_stack),
		   CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
	if (c1 < 0) {
		perror("clone C1");
		exit(1);
	}

	/* P writes A's maps for C1 */
	if (write_map_at("/proc", c1, "uid_map", "0 20000 20000\n100000 200000 50000") ||
	    write_map_at("/proc", c1, "gid_map", "0 400000 50000\n50000 500000 100000")) {
		printf("P: FAILED TO SETUP C1 MAPS\n");
		exit(1);
	}

	/* tell C1 the maps are in place */
	{
		int rfd = open(READY, O_WRONLY | O_CREAT | O_TRUNC, 0666);

		if (rfd < 0) {
			perror("create " READY);
			exit(1);
		}
		close(rfd);
	}

	/* wait for C1 to create C2 and report its local pid */
	sleep(6);

	fd = open("/tmp/c2pid", O_RDONLY);
	len = read(fd, buf, sizeof(buf) - 1);
	buf[len] = 0;
	close(fd);
	int c2l = atoi(buf);
	printf("P: c2 pid in C1's pidns = %d\n", c2l);

	/* find C2's global pid via C1's children */
	{
		char path[64], children[64];
		int cfd, clen;

		snprintf(path, sizeof(path), "/proc/%d/task/%d/children", c1, c1);
		cfd = open(path, O_RDONLY);
		clen = read(cfd, children, sizeof(children) - 1);
		children[clen] = 0;
		close(cfd);
		c2g = atoi(children);
		printf("P: c2 global pid = %d\n", c2g);
	}

	/*
	 * Test 1: P writes C2's maps through the init /proc.
	 * Expected: FAIL (procfs mount does not belong to A).
	 */
	if (write_map_at("/proc", c2g, "uid_map", "0 100000 50000\n"))
		printf("TEST1 (init /proc): WRITE FAILED\n");
	else
		printf("TEST1 (init /proc): WRITE OK\n");

	/*
	 * Test 2: P forks a worker, which enters A (like the usernsd
	 * daemon does) and the mount namespace of C1, and writes C2's
	 * maps through the procfs mounted in A, by the pid from C1's
	 * pid namespace.
	 */
	{
		int worker, wstatus;

		worker = fork();
		if (worker == 0) {
			char path[64];
			int nsfd;

			snprintf(path, sizeof(path), "/proc/%d/ns/mnt", c1);
			nsfd = open(path, O_RDONLY);
			if (nsfd < 0) {
				perror("open c1 mntns");
				_exit(1);
			}
			if (setns(nsfd, CLONE_NEWNS)) {
				perror("worker setns mnt");
				_exit(1);
			}
			close(nsfd);

			/*
			 * Enter the mount namespace first, while we still
			 * have the capabilities of the initial user namespace
			 * to reach it, and the user namespace after that.
			 */
			snprintf(path, sizeof(path), "/proc/%d/ns/user", c1);
			nsfd = open(path, O_RDONLY);
			if (nsfd < 0) {
				perror("open c1 userns");
				_exit(1);
			}
			if (setns(nsfd, CLONE_NEWUSER)) {
				perror("worker setns A");
				_exit(1);
			}
			close(nsfd);

			if (write_map_at(PROC_A, c2l, "uid_map", "0 100000 50000\n"))
				_exit(2);
			_exit(0);
		}

		if (waitpid(worker, &wstatus, 0) != worker)
			exit(1);

		if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus))
			printf("TEST2 (A procfs, worker in A): WRITE FAILED (%d)\n", wstatus);
		else
			printf("TEST2 (A procfs, worker in A): WRITE OK\n");
	}

	/*
	 * Test 2b: worker in A, writing through the init-mounted /proc
	 * by the global pid of C2. Discriminates whether the kernel
	 * checks the procfs mount's user namespace.
	 */
	{
		int worker, wstatus;

		worker = fork();
		if (worker == 0) {
			char path[64];
			int nsfd;

			snprintf(path, sizeof(path), "/proc/%d/ns/user", c1);
			nsfd = open(path, O_RDONLY);
			if (nsfd < 0) {
				perror("open c1 userns");
				_exit(1);
			}
			if (setns(nsfd, CLONE_NEWUSER)) {
				perror("worker setns A");
				_exit(1);
			}
			close(nsfd);

			/*
			 * Write through an fd of the /proc directory, like
			 * the restored task does via the criu /proc service fd.
			 */
			if (write_map_at_fd(proc_fd, c2g, "gid_map", "0 50000 100000\n"))
				_exit(2);
			_exit(0);
		}

		if (waitpid(worker, &wstatus, 0) != worker)
			exit(1);

		if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus))
			printf("TEST2b (init procfs, worker in A): WRITE FAILED (%d)\n", wstatus);
		else
			printf("TEST2b (init procfs, worker in A): WRITE OK\n");
	}

	waitpid(c1, &status, 0);
	printf("C1 status %d\n", status);
	return 0;
}
