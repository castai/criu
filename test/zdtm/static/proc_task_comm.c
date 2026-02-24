/*
 * Test that CRIU can checkpoint/restore a process that has an open fd
 * referencing /proc/self/task/<tid>/comm where the thread <tid> has
 * already exited. This reproduces a bug seen with Rust applications
 * using Prometheus metrics libraries that hold open fds to per-thread
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

const char *test_doc = "Check C/R of fd referencing /proc/self/task/<dead_tid>/comm";
const char *test_author = "CRIU developers";

static int thread_fd = -1;
static pid_t thread_tid;

static void *thread_fn(void *arg)
{
	char path[128];

	thread_tid = syscall(__NR_gettid);

	/*
	 * Open our own /proc/self/task/<tid>/comm. The kernel resolves
	 * /proc/self to /proc/<pid>, so the stored path will be
	 * /proc/<pid>/task/<tid>/comm with numeric PID and TID.
	 */
	snprintf(path, sizeof(path), "/proc/self/task/%d/comm", thread_tid);
	thread_fd = open(path, O_RDONLY);
	if (thread_fd < 0) {
		pr_perror("Failed to open %s in thread", path);
		return (void *)1;
	}

	test_msg("Thread %d opened %s as fd %d\n", thread_tid, path, thread_fd);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t th;
	void *retval;
	int ret;

	test_init(argc, argv);

	/* Create a thread that opens its own /proc/self/task/<tid>/comm */
	ret = pthread_create(&th, NULL, thread_fn, NULL);
	if (ret) {
		pr_perror("pthread_create failed");
		return 1;
	}

	/* Wait for the thread to finish — it has opened the fd and exited */
	ret = pthread_join(th, &retval);
	if (ret) {
		pr_perror("pthread_join failed");
		return 1;
	}

	if (retval != NULL) {
		fail("Thread failed to open proc file");
		return 1;
	}

	if (thread_fd < 0) {
		fail("Thread did not produce a valid fd");
		return 1;
	}

	/*
	 * At this point:
	 * - thread_fd points to /proc/<pid>/task/<dead_tid>/comm
	 * - The thread with <dead_tid> has exited
	 * - The fd is still valid (held open by the process)
	 *
	 * CRIU will dump this fd with the path stored as-is. On restore,
	 * the dead thread's TID won't exist, so openat() will fail with
	 * ENOENT unless CRIU handles this case.
	 */
	test_msg("Thread %d has exited, fd %d still open\n",
		 thread_tid, thread_fd);

	test_daemon();
	test_waitsig();

	/*
	 * After restore, verify the fd is still valid.
	 * We only check F_GETFD — the thread is dead, so the file content
	 * may not be meaningful, but the fd must be valid.
	 */
	ret = fcntl(thread_fd, F_GETFD);
	if (ret < 0) {
		fail("fd %d is not valid after restore: %s",
		     thread_fd, strerror(errno));
		close(thread_fd);
		return 1;
	}

	close(thread_fd);
	pass();
	return 0;
}
