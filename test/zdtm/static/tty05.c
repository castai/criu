/*
 * tty05 - PTY master held by parent, child has /dev/tty open; --shell-job must
 *         allow dump+restore to succeed.
 *
 * Reproduces the "ctty inheritance detected" dump failure fixed in
 * tty_verify_ctty():
 *
 *   Error (criu/tty.c): tty: ctty inheritance detected sid/pgrp N
 *                       (ctty pid_real A pty pid_real B)
 *
 * The trigger condition is:
 *   - A process (child, pid_real A) has /dev/tty open (TTY_TYPE__CTTY).
 *   - A PTY entry in the same session has a different pid_real (parent, B).
 *   - pid_real A != pid_real B → CRIU aborts without --shell-job.
 *
 * Setup:
 *   1. Parent opens /dev/ptmx (PTY master) and keeps it open.
 *      CRIU will record this as a PTY entry with pid_real = parent.
 *   2. Child calls setsid() + opens the PTY slave + TIOCSCTTY so the slave
 *      becomes the child's controlling terminal.
 *   3. Child opens /dev/tty explicitly.
 *      CRIU records this as TTY_TYPE__CTTY with pid_real = child.
 *   4. pid_real(ctty) != pid_real(pty master holder) → "ctty inheritance".
 *
 * With --shell-job (injected via tty05.desc) tty_verify_ctty() must log an
 * info message and continue.  After restore the child's /dev/tty fd must still
 * be a valid terminal.
 */

#define _XOPEN_SOURCE 500
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "PTY master/ctty pid_real mismatch: --shell-job must allow dump+restore";
const char *test_author	= "CAST AI";

int main(int argc, char **argv)
{
	int fdm, fds, dev_tty_fd;
	char *slavename;
	task_waiter_t t;
	pid_t pid;
	int status;

	test_init(argc, argv);
	task_waiter_init(&t);

	/* Step 1: parent opens the PTY master and keeps it open. */
	fdm = open("/dev/ptmx", O_RDWR);
	if (fdm == -1) {
		pr_perror("open /dev/ptmx");
		return 1;
	}

	if (grantpt(fdm) || unlockpt(fdm)) {
		pr_perror("grantpt/unlockpt");
		close(fdm);
		return 1;
	}

	slavename = ptsname(fdm);
	if (!slavename) {
		pr_perror("ptsname");
		close(fdm);
		return 1;
	}

	/*
	 * Step 2: fork the child.  It will become the session leader with the
	 * PTY slave as its controlling terminal and open /dev/tty.
	 */
	pid = test_fork();
	if (pid < 0) {
		pr_perror("test_fork");
		close(fdm);
		return 1;
	}

	if (pid == 0) {
		/* ---- child ---- */
		close(fdm); /* child does not need the master */

		/* New session: child becomes session leader. */
		if (setsid() == -1) {
			pr_perror("child: setsid");
			exit(1);
		}

		/* Open slave and make it the controlling terminal. */
		fds = open(slavename, O_RDWR);
		if (fds == -1) {
			pr_perror("child: open slave");
			exit(1);
		}

		if (ioctl(fds, TIOCSCTTY, 1) < 0) {
			pr_perror("child: TIOCSCTTY");
			close(fds);
			exit(1);
		}

		/*
		 * Step 3: open /dev/tty explicitly.  This creates the
		 * TTY_TYPE__CTTY entry in the CRIU dump with pid_real = child.
		 * Combined with the master (pid_real = parent) this triggers
		 * "ctty inheritance detected" without --shell-job.
		 */
		dev_tty_fd = open("/dev/tty", O_RDWR);
		if (dev_tty_fd == -1) {
			pr_perror("child: open /dev/tty");
			close(fds);
			exit(1);
		}

		/* Signal the parent that setup is complete. */
		task_waiter_complete(&t, 1);

		/* Wait for C/R to complete. */
		test_waitsig();

		/* Step 4: after restore, /dev/tty must still be a terminal. */
		if (!isatty(dev_tty_fd)) {
			fail("/dev/tty fd is no longer a tty after restore");
			close(dev_tty_fd);
			close(fds);
			exit(1);
		}

		close(dev_tty_fd);
		close(fds);
		exit(0);
	}

	/* ---- parent ---- */

	/* Wait for child to set up its controlling terminal. */
	task_waiter_wait4(&t, 1);

	/*
	 * Parent keeps fdm open throughout the C/R cycle.  This is the PTY
	 * entry whose pid_real != child's pid_real, triggering the check.
	 */
	test_daemon();
	test_waitsig();

	if (waitpid(pid, &status, 0) < 0) {
		pr_perror("waitpid");
		close(fdm);
		return 1;
	}

	close(fdm);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("child exited with status %d", status);
		return 1;
	}

	pass();
	return 0;
}
