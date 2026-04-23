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

const char *test_doc = "Test external unix stream socket with --ext-unix-sk\n";
const char *test_author = "Filipe Augusto Lima de Souza <filipe@cast.ai>";

/*
 * Mirrors the multi-container scenario: one process binds a named
 * AF_UNIX SOCK_STREAM listener and accepts a single client; the other
 * process connects to that path. After C/R both sides must be able to
 * continue the conversation (queue replay + live connection).
 *
 * The client is marked as "external" via test_ext_init() so the ZDTM
 * harness excludes it from the dump tree, forcing CRIU to take the
 * external-socket path (sk-unix.c). Today this path rejects stream
 * external sockets (sk-unix.c:912) — the test is expected to fail
 * until the dump-side changes land.
 */

#define MSG_C2S  "hello-from-client"
#define MSG_S2C  "hello-from-server"
#define MSG_POST "post-restore-ok"

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	task_waiter_t lock;
	char dir[] = "/tmp/zdtm.unix.stream.XXXXXX";
	char *path;
	pid_t pid;
	int ret;
	int ssk, asock;
	char buf[64];

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
		/*
		 * Child: the "client". Marked external via test_ext_init()
		 * so it is not part of the dumped process tree.
		 */
		int csk;
		char buf[64];

		test_ext_init(argc, argv);

		/* Wait for server to bind+listen */
		task_waiter_wait4(&lock, 1);

		csk = socket(AF_UNIX, SOCK_STREAM, 0);
		if (csk < 0) {
			pr_perror("client socket");
			return 1;
		}
		if (connect(csk, (struct sockaddr *)&addr, addrlen) < 0) {
			pr_perror("client connect");
			return 1;
		}

		if (write(csk, MSG_C2S, strlen(MSG_C2S)) != (ssize_t)strlen(MSG_C2S)) {
			pr_perror("client pre-dump write");
			return 1;
		}

		/* Signal server: client is connected and has written */
		task_waiter_complete(&lock, 2);

		/* Read server's pre-dump greeting */
		memset(buf, 0, sizeof(buf));
		ret = read(csk, buf, sizeof(buf) - 1);
		if (ret <= 0) {
			pr_perror("client pre-dump read");
			return 1;
		}
		if (strcmp(buf, MSG_S2C) != 0) {
			fail("client got unexpected pre-dump msg: %s", buf);
			return 1;
		}

		/* Wait for server to have been restored and greeted us */
		task_waiter_wait4(&lock, 3);

		memset(buf, 0, sizeof(buf));
		ret = read(csk, buf, sizeof(buf) - 1);
		if (ret <= 0) {
			pr_perror("client post-dump read");
			return 1;
		}
		if (strcmp(buf, MSG_POST) != 0) {
			fail("client got unexpected post-dump msg: %s", buf);
			return 1;
		}

		close(csk);
		task_waiter_complete(&lock, 4);
		task_waiter_fini(&lock);
		return 0;
	}

	/*
	 * Parent: the "server". This is the process CRIU dumps.
	 */
	test_init(argc, argv);

	ssk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ssk < 0) {
		pr_perror("server socket");
		goto out_kill;
	}
	if (bind(ssk, (struct sockaddr *)&addr, addrlen) < 0) {
		pr_perror("server bind");
		goto out_kill;
	}
	chmod(dir, 0777);
	chmod(path, 0777);
	if (listen(ssk, 1) < 0) {
		pr_perror("server listen");
		goto out_kill;
	}

	/* Release the client to connect */
	task_waiter_complete(&lock, 1);

	asock = accept(ssk, NULL, NULL);
	if (asock < 0) {
		pr_perror("server accept");
		goto out_kill;
	}

	/* Wait until client wrote its pre-dump message */
	task_waiter_wait4(&lock, 2);

	memset(buf, 0, sizeof(buf));
	ret = read(asock, buf, sizeof(buf) - 1);
	if (ret <= 0) {
		pr_perror("server pre-dump read");
		goto out_kill;
	}
	if (strcmp(buf, MSG_C2S) != 0) {
		fail("server got unexpected pre-dump msg: %s", buf);
		goto out_kill;
	}

	if (write(asock, MSG_S2C, strlen(MSG_S2C)) != (ssize_t)strlen(MSG_S2C)) {
		pr_perror("server pre-dump write");
		goto out_kill;
	}

	test_daemon();
	test_waitsig();

	/* Post-restore: both asock and the client's csk must still work */
	if (write(asock, MSG_POST, strlen(MSG_POST)) != (ssize_t)strlen(MSG_POST)) {
		pr_perror("server post-dump write");
		goto out_kill;
	}

	/* Let the client read and validate */
	task_waiter_complete(&lock, 3);
	task_waiter_wait4(&lock, 4);
	task_waiter_fini(&lock);

	waitpid(pid, NULL, 0);

	close(asock);
	close(ssk);
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
