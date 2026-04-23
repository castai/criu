#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Dump/restore a connected AF_UNIX stream socket whose peer is external (--ext-unix-sk)\n";
const char *test_author = "Filipe Augusto Lima de Souza <filipe@cast.ai>";

/*
 * Parent = CLIENT, child = external SERVER. The parent connect()s and
 * holds the fd open across dump+restore. The external child keeps its
 * listener AND accepted fd open (blocked on read) so the parent's
 * socket is in normal ESTABLISHED state (not semi-closed) at dump time.
 *
 * This covers the dump path for a stream socket connected to an
 * external peer, and the restore path that must recreate that
 * connection via the listener path recovered by getpeername() at dump.
 *
 * Post-restore we only assert dump+restore succeeded — we do not
 * assert end-to-end data exchange, because with a single-dump harness
 * the surviving child's accepted-fd kernel state diverges from
 * whatever the restored client points at. The customer's full
 * two-container test at the orchestrator level covers that.
 */

#define MSG_C2S  "hello-from-client"

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t lock;
	char dir[] = "/tmp/zdtm.unix.stream.XXXXXX";
	char *path;
	pid_t pid;
	int csk;

	if (mkdtemp(dir) == NULL) {
		pr_perror("mkdtemp(%s)", dir);
		return 1;
	}
	chmod(dir, 0777);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", dir, "sock");
	path = addr.sun_path;
	addrlen = sizeof(addr.sun_family) + strlen(path);

	task_waiter_init(&lock);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		int ssk, asock;
		char cbuf[64];

		/*
		 * Detach from the parent's process group so the zdtm
		 * harness's group-targeted SIGKILL after dump doesn't
		 * reap us. We need to stay alive through restore to
		 * accept the parent's reconnect.
		 */
		if (setsid() < 0) {
			pr_perror("child setsid");
			exit(1);
		}

		test_ext_init(argc, argv);

		ssk = socket(AF_UNIX, SOCK_STREAM, 0);
		if (ssk < 0) {
			pr_perror("child socket");
			return 1;
		}
		if (bind(ssk, (struct sockaddr *)&addr, addrlen) < 0) {
			pr_perror("child bind");
			return 1;
		}
		chmod(dir, 0777);
		chmod(path, 0777);
		if (listen(ssk, 8) < 0) {
			pr_perror("child listen");
			return 1;
		}

		task_waiter_complete(&lock, 1);

		asock = accept(ssk, NULL, NULL);
		if (asock < 0) {
			pr_perror("child accept");
			return 1;
		}

		/*
		 * Read once pre-dump so we know the parent's connect
		 * actually went through before dump time. Then block on
		 * read again to keep the connection ESTABLISHED (not
		 * semi-closed) throughout parent C/R.
		 */
		if (read(asock, cbuf, sizeof(cbuf) - 1) <= 0) {
			pr_perror("child pre-dump read");
			return 1;
		}

		/*
		 * Hold the listener open indefinitely so the parent's
		 * restore can connect to it. The parent will SIGKILL us
		 * when the test concludes.
		 */
		while (1)
			pause();

		/* unreachable */
		return 0;
	}

	/* Parent: client */
	test_init(argc, argv);

	task_waiter_wait4(&lock, 1);

	csk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (csk < 0) {
		pr_perror("parent socket");
		goto out_kill;
	}
	if (connect(csk, (struct sockaddr *)&addr, addrlen) < 0) {
		pr_perror("parent connect");
		goto out_kill;
	}

	if (write(csk, MSG_C2S, strlen(MSG_C2S)) != (ssize_t)strlen(MSG_C2S)) {
		pr_perror("parent pre-dump write");
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Assert fd is still valid post-restore. A stricter check
	 * (successful round-trip) requires orchestrator-level control
	 * and lives in the CRI integration test suite.
	 */
	{
		int type = 0;
		socklen_t len = sizeof(type);
		if (getsockopt(csk, SOL_SOCKET, SO_TYPE, &type, &len) < 0) {
			pr_perror("parent post-restore getsockopt");
			goto out_kill;
		}
		if (type != SOCK_STREAM) {
			fail("parent post-restore fd is not SOCK_STREAM (got %d)", type);
			goto out_kill;
		}
	}

	close(csk);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	unlink(path);
	rmdir(dir);

	pass();
	return 0;

out_kill:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	unlink(path);
	rmdir(dir);
	fail();
	return 1;
}
