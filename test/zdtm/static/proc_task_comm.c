/*
 * Test that CRIU can checkpoint/restore a process that has open fds
 * referencing /proc/self/task/<tid>/... for both dead and live threads.
 *
 * Dead thread case: the thread opens /proc/self/task/<tid>/comm and
 * then exits. The fd survives but the tid no longer exists on restore.
 *
 * Live thread case: the thread opens /proc/self/task/<tid>/stat and
 * stays alive through C/R. After restore, the fd must still read the
 * correct thread's stat (not the leader's).
 *
 * This reproduces bugs seen with Rust applications using Prometheus
 * metrics libraries that hold open fds to per-thread
 * /proc/self/task/<tid>/stat files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syscall.h>

#include "zdtmtst.h"

const char *test_doc = "Check C/R of fd referencing /proc/self/task/<tid>/... for dead and live threads";
const char *test_author = "CRIU developers";

/* Dead thread state */
static int dead_thread_fd = -1;
static pid_t dead_thread_tid;

/* Live thread state */
static int live_thread_fd = -1;
static pid_t live_thread_tid;
static volatile int live_thread_ready;

/*
 * Dead thread: opens /proc/self/task/<tid>/comm, then exits.
 * The fd remains open but the thread is gone.
 */
static void *dead_thread_fn(void *arg)
{
	char path[128];

	dead_thread_tid = syscall(__NR_gettid);

	snprintf(path, sizeof(path), "/proc/self/task/%d/comm", dead_thread_tid);
	dead_thread_fd = open(path, O_RDONLY);
	if (dead_thread_fd < 0) {
		pr_perror("Failed to open %s in dead thread", path);
		return (void *)1;
	}

	test_msg("Dead thread %d opened %s as fd %d\n",
		 dead_thread_tid, path, dead_thread_fd);
	return NULL;
}

/*
 * Live thread: opens /proc/self/task/<tid>/stat, signals readiness,
 * then stays alive through C/R.
 */
static void *live_thread_fn(void *arg)
{
	char path[128];

	live_thread_tid = syscall(__NR_gettid);

	snprintf(path, sizeof(path), "/proc/self/task/%d/stat", live_thread_tid);
	live_thread_fd = open(path, O_RDONLY);
	if (live_thread_fd < 0) {
		pr_perror("Failed to open %s in live thread", path);
		return (void *)1;
	}

	test_msg("Live thread %d opened %s as fd %d\n",
		 live_thread_tid, path, live_thread_fd);

	/* Signal main thread that we're ready */
	live_thread_ready = 1;

	/* Stay alive through C/R */
	while (live_thread_ready != 2)
		usleep(10000);

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t dead_th, live_th;
	void *retval;
	char buf[512];
	int ret;
	pid_t read_tid;

	test_init(argc, argv);

	/* --- Set up dead thread fd --- */
	ret = pthread_create(&dead_th, NULL, dead_thread_fn, NULL);
	if (ret) {
		pr_perror("pthread_create (dead) failed");
		return 1;
	}

	ret = pthread_join(dead_th, &retval);
	if (ret) {
		pr_perror("pthread_join (dead) failed");
		return 1;
	}

	if (retval != NULL) {
		fail("Dead thread failed to open proc file");
		return 1;
	}

	if (dead_thread_fd < 0) {
		fail("Dead thread did not produce a valid fd");
		return 1;
	}

	/* --- Set up live thread fd --- */
	ret = pthread_create(&live_th, NULL, live_thread_fn, NULL);
	if (ret) {
		pr_perror("pthread_create (live) failed");
		return 1;
	}

	/* Wait for live thread to be ready */
	while (!live_thread_ready)
		usleep(1000);

	if (live_thread_fd < 0) {
		fail("Live thread did not produce a valid fd");
		return 1;
	}

	/*
	 * At this point:
	 * - dead_thread_fd -> /proc/<pid>/task/<dead_tid>/comm (thread exited)
	 * - live_thread_fd -> /proc/<pid>/task/<live_tid>/stat (thread alive)
	 */
	test_msg("Dead thread %d exited, fd %d still open\n",
		 dead_thread_tid, dead_thread_fd);
	test_msg("Live thread %d alive, fd %d open\n",
		 live_thread_tid, live_thread_fd);

	test_daemon();
	test_waitsig();

	/* --- Verify dead thread fd: must be valid (F_GETFD check) --- */
	ret = fcntl(dead_thread_fd, F_GETFD);
	if (ret < 0) {
		fail("Dead thread fd %d is not valid after restore",
		     dead_thread_fd);
		goto out;
	}
	test_msg("Dead thread fd %d is valid after restore\n", dead_thread_fd);

	/* --- Verify live thread fd: must read the correct tid --- */
	ret = lseek(live_thread_fd, 0, SEEK_SET);
	if (ret < 0) {
		fail("lseek failed on live thread fd");
		goto out;
	}

	ret = read(live_thread_fd, buf, sizeof(buf) - 1);
	if (ret <= 0) {
		fail("read failed on live thread fd: %d", ret);
		goto out;
	}
	buf[ret] = '\0';

	/*
	 * /proc/<pid>/task/<tid>/stat starts with "<tid> (comm) ..."
	 * Verify the tid matches the live thread's tid, proving that
	 * the fd points to the correct thread (not the leader).
	 */
	read_tid = atoi(buf);
	if (read_tid != live_thread_tid) {
		fail("Wrong tid in stat: expected %d, got %d. Content: %.80s",
		     live_thread_tid, read_tid, buf);
		goto out;
	}

	test_msg("Live thread fd reads correct tid %d after restore\n",
		 live_thread_tid);

	close(dead_thread_fd);
	close(live_thread_fd);
	pass();

	live_thread_ready = 2;
	pthread_join(live_th, NULL);
	return 0;

out:
	close(dead_thread_fd);
	close(live_thread_fd);
	live_thread_ready = 2;
	pthread_join(live_th, NULL);
	return 1;
}
