/*
 * tty04 - Verify that --shell-job on restore of a non-tty process does not fail.
 *
 * When --shell-job is passed (e.g. by a container runtime like runc that always
 * passes the flag), but the dumped process has no controlling terminal, CRIU
 * must silently succeed instead of returning an error.
 *
 * This test runs as a plain process with no terminal.  The .desc file passes
 * --shell-job to both dump and restore.  A successful C/R cycle proves the fix.
 *
 * Coverage: This test exercises the tty_prep_fds() early-return path when
 * stdin is not a tty.  It does NOT cover the pty_open_unpaired_slave() fake-
 * master fallback path (triggered when a PTY slave exists but stdin is not a
 * tty), nor the tty_find_restoring_task() notask path (triggered when a TTY's
 * session leader is absent from the dump).  Those paths require a process tree
 * with PTY file descriptors and are harder to construct in the zdtm framework.
 */

#include "zdtmtst.h"

const char *test_doc	= "Restore with --shell-job on a process with no tty";
const char *test_author	= "CAST AI";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
