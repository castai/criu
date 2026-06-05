/*
 * tty04 - Verify that --shell-job succeeds when the process has no
 *         controlling terminal.
 *
 * Callers such as runc always pass --shell-job when checkpointing
 * containers.  The process being dumped may or may not have a
 * controlling terminal.  When it does not, CRIU should not fail —
 * it should silently skip the tty inheritance setup.
 *
 * This test runs a plain process that has no controlling terminal
 * (test_init() calls setsid() which detaches it from any terminal)
 * and validates that criu dump/restore with --shell-job succeeds.
 */

#include <unistd.h>
#include "zdtmtst.h"

const char *test_doc	= "Dump/restore with --shell-job when process has no tty";
const char *test_author	= "CAST AI";

int main(int argc, char **argv)
{
	test_init(argc, argv);

	/*
	 * The process has no controlling terminal: test_init() called
	 * setsid() which detaches from any terminal.  The test runner
	 * passes --shell-job via the .desc opts.  CRIU must not fail
	 * when shell-job is set but stdin is not a tty.
	 */
	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
