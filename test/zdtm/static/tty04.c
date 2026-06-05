/*
 * tty04 - Validate auto-detection of shell-job TTY without --shell-job flag.
 *
 * This test verifies that CRIU can checkpoint and restore a process that has
 * an open PTY slave fd whose session ID (SID) points to a process outside the
 * dump tree, without requiring the caller to pass --shell-job explicitly.
 *
 * The scenario mirrors the container runtime use-case (e.g. runc): the
 * container runtime is the session leader / PTY owner, while the contained
 * process is dumped without the runtime being part of the dump tree.
 *
 * How it works:
 *   1. Before test_init(), a helper child is forked.  The helper calls
 *      setsid() and TIOCSCTTY to become the session leader for the PTY slave.
 *   2. The parent (which will become the ZDTM test process via test_init())
 *      retains an open fd to the PTY slave.
 *   3. test_init() forks and the test child calls setsid(), creating a new
 *      session and detaching from any controlling terminal.  The slave fd is
 *      inherited but the slave's TIOCGSID still returns the helper's SID.
 *   4. When CRIU dumps the test process, TIOCGSID on the slave fd returns the
 *      helper's PID (which is outside the dump tree), triggering the
 *      auto-detect path in dump_verify_tty_sids() that sets opts.shell_job
 *      without the caller having passed --shell-job.
 *   5. After restore, the test verifies that the slave fd is still a valid tty.
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

const char *test_doc	= "Auto-detect shell-job TTY without --shell-job flag";
const char *test_author	= "CAST AI";

/*
 * PID of the external helper that owns the PTY session.  Stored before
 * test_init() so that it is inherited into the ZDTM test process.
 */
static pid_t helper_pid = -1;

static void cleanup_helper(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;

	kill(pid, SIGTERM);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		break;
	}
}

int main(int argc, char **argv)
{
	int fdm, fds;
	char *slavename;
	int sync_pipe[2];
	char buf;

	/*
	 * Step 1: open a PTY master before daemonising so the helper can
	 * set up the controlling terminal.
	 */
	fdm = open("/dev/ptmx", O_RDWR);
	if (fdm == -1) {
		pr_perror("Can't open master pseudoterminal");
		return 1;
	}

	if (grantpt(fdm) || unlockpt(fdm)) {
		pr_perror("grantpt/unlockpt failed");
		close(fdm);
		return 1;
	}

	slavename = ptsname(fdm);
	if (!slavename) {
		pr_perror("ptsname failed");
		close(fdm);
		return 1;
	}

	if (pipe(sync_pipe) == -1) {
		pr_perror("pipe failed");
		close(fdm);
		return 1;
	}

	/*
	 * Step 2: fork the helper.  It becomes the session leader for the
	 * PTY slave — this process is deliberately NOT part of the CRIU
	 * dump tree.
	 */
	helper_pid = fork();
	if (helper_pid < 0) {
		pr_perror("fork helper failed");
		close(fdm);
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return 1;
	}

	if (helper_pid == 0) {
		/* ---- helper child ---- */
		int slave_fd;

		close(sync_pipe[0]);
		close(fdm);

		if (setsid() == -1) {
			pr_perror("helper: setsid failed");
			_exit(1);
		}

		slave_fd = open(slavename, O_RDWR);
		if (slave_fd == -1) {
			pr_perror("helper: open slave failed");
			_exit(1);
		}

		if (ioctl(slave_fd, TIOCSCTTY, 1) < 0) {
			pr_perror("helper: TIOCSCTTY failed");
			_exit(1);
		}

		/* Signal the parent that setup is complete. */
		if (write(sync_pipe[1], "1", 1) != 1) {
			pr_perror("helper: write sync_pipe failed");
			_exit(1);
		}
		close(sync_pipe[1]);

		/*
		 * Stay alive until killed: the test process sends SIGTERM
		 * after the C/R cycle completes.
		 */
		while (1)
			pause();

		_exit(0);
	}

	/* ---- parent / future test process ---- */
	close(sync_pipe[1]);

	/* Wait for the helper to finish setting up TIOCSCTTY. */
	if (read(sync_pipe[0], &buf, 1) != 1) {
		pr_perror("read sync_pipe failed");
		close(sync_pipe[0]);
		cleanup_helper(helper_pid);
		close(fdm);
		return 1;
	}
	close(sync_pipe[0]);

	/*
	 * Step 3: open the slave fd in the parent.  After test_init() forks
	 * and the test child calls setsid(), this fd is inherited but
	 * TIOCGSID still points to helper_pid's SID — outside the dump tree.
	 */
	fds = open(slavename, O_RDWR | O_NOCTTY);
	if (fds == -1) {
		pr_perror("Can't open slave pseudoterminal %s", slavename);
		cleanup_helper(helper_pid);
		close(fdm);
		return 1;
	}

	/* We no longer need the master in the test process. */
	close(fdm);

	/*
	 * Step 4: hand off to the ZDTM framework.  test_init() will fork;
	 * the child calls setsid() (new session, no controlling terminal)
	 * but fds is inherited.  TIOCGSID(fds) → helper's SID → outside
	 * dump tree → CRIU auto-detects shell-job.
	 */
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	/*
	 * Step 5: after restore, verify the slave fd is still a valid tty.
	 */
	if (!isatty(fds)) {
		fail("Slave fd is no longer a tty after restore");
		cleanup_helper(helper_pid);
		return 1;
	}

	/* Clean up the helper. */
	cleanup_helper(helper_pid);

	pass();
	return 0;
}
