#include "zdtmtst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <netinet/tcp.h>

const char *test_doc = "Check that sk_uid is preserved on inet socket C/R\n";
const char *test_author = "Dmytro Bainak <dmytro.bainak@cast.ai>";

#define TEST_UID	1337
#define BUF_SIZE	4096

static int port = 8880;

/*
 * Look up the uid column in /proc/net/tcp for the row whose inode
 * matches `ino`. Inode is unique across sockets, so this avoids
 * confusing the LISTEN sk with the ESTABLISHED accepted sk that
 * share the same local port.
 */
static uid_t sk_uid_for_inode(unsigned long ino)
{
	FILE *f;
	char line[512];
	uid_t found = (uid_t)-1;

	f = fopen("/proc/net/tcp", "r");
	if (!f) {
		pr_perror("open /proc/net/tcp");
		return (uid_t)-1;
	}

	if (!fgets(line, sizeof(line), f))
		goto out;

	while (fgets(line, sizeof(line), f)) {
		unsigned int uid;
		unsigned long inode;
		/*
		 * sl  local rem  st  tx:rx  tr:when  retr  uid  to  inode
		 *  *   *    *    *    *      *        *    %u   *   %lu
		 */
		if (sscanf(line, " %*s %*s %*s %*s %*s %*s %*s %u %*s %lu",
			   &uid, &inode) != 2)
			continue;
		if (inode == ino) {
			found = (uid_t)uid;
			break;
		}
	}
out:
	fclose(f);
	return found;
}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s, fd_c;
	pid_t cpid;
	uint32_t crc;
	int pfd[2];
	struct stat st;
	uid_t got;

	test_init(argc, argv);

	if (pipe(pfd)) {
		pr_perror("pipe");
		return 1;
	}

	cpid = fork();
	if (cpid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (cpid == 0) {
		/* Child: plain TCP client. Its only job is to keep the
		 * connection peer alive across C/R and echo one buffer. */
		close(pfd[1]);
		if (read(pfd[0], &port, sizeof(port)) != sizeof(port)) {
			pr_perror("read port");
			return 1;
		}
		close(pfd[0]);

		fd_c = tcp_init_client(AF_INET, "localhost", port);
		if (fd_c < 0)
			return 1;

		if (read_data(fd_c, buf, BUF_SIZE)) {
			pr_perror("client read");
			return 1;
		}
		if (datachk(buf, BUF_SIZE, &crc))
			return 2;
		datagen(buf, BUF_SIZE, &crc);
		if (write_data(fd_c, buf, BUF_SIZE)) {
			pr_perror("client write");
			return 1;
		}
		return 0;
	}

	if ((fd_s = tcp_init_server(AF_INET, &port)) < 0) {
		pr_err("server init failed\n");
		return 1;
	}

	close(pfd[0]);
	if (write(pfd[1], &port, sizeof(port)) != sizeof(port)) {
		pr_perror("send port");
		return 1;
	}
	close(pfd[1]);

	/*
	 * The kernel reads current_fsuid() in sock_init_data() at socket
	 * birth, which for an accepted socket is inside accept(). Switch
	 * fsuid around accept() so the new sk gets sk_uid = TEST_UID
	 * while euid stays root (required for CRIU to checkpoint TCP).
	 */
	setfsuid(TEST_UID);
	if ((uid_t)setfsuid(-1) != TEST_UID) {
		pr_err("setfsuid(TEST_UID) did not take effect\n");
		return 1;
	}
	fd = tcp_accept_server(fd_s);
	setfsuid(0);
	if (fd < 0) {
		pr_err("accept failed\n");
		return 1;
	}

	/* Pre-dump: confirm the kernel agrees the stamp took, so a
	 * failure after C/R is unambiguously a restore-side regression. */
	if (fstat(fd, &st)) {
		pr_perror("fstat pre-dump");
		return 1;
	}
	got = sk_uid_for_inode(st.st_ino);
	if (got != TEST_UID) {
		fail("pre-dump: sk_uid is %u, want %u (inode %lu)",
		     got, TEST_UID, st.st_ino);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* Restored socket gets a fresh kernel inode; re-fstat to find it. */
	if (fstat(fd, &st)) {
		pr_perror("fstat post-restore");
		return 1;
	}
	got = sk_uid_for_inode(st.st_ino);
	if (got != TEST_UID) {
		fail("post-restore: sk_uid is %u, want %u (inode %lu)",
		     got, TEST_UID, st.st_ino);
		return 1;
	}

	/* Light connection-integrity check, same shape as socket-tcp-local. */
	datagen(buf, BUF_SIZE, &crc);
	if (write_data(fd, buf, BUF_SIZE)) {
		pr_perror("parent write after restore");
		return 1;
	}
	if (read_data(fd, buf, BUF_SIZE)) {
		pr_perror("parent read after restore");
		return 1;
	}
	if (datachk(buf, BUF_SIZE, &crc)) {
		fail("data integrity check failed");
		return 2;
	}

	pass();
	return 0;
}
