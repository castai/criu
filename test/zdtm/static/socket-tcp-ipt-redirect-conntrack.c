#include "zdtmtst.h"

const char *test_doc = "Check TCP DNAT (iptables REDIRECT) conntrack survives C/R\n";
const char *test_author = "Dmytro Bainak <dbaynak@protonmail.com>";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#define BUF_SIZE   4096
#define REDIR_PORT 12345

int read_write_data(int fd, unsigned char *buf, size_t len, uint32_t* crc) {
    if (read_data(fd, buf, len)) {
        pr_perror("read less than have to (pre)");
        return 1;
    }
    if (datachk(buf, len, crc))
        return 2;
    datagen(buf, BUF_SIZE, crc);
    if (write_data(fd, buf, BUF_SIZE)) {
        pr_perror("can't write (pre)");
        return 1;
    }
    return 0;
}

int write_read_data(int fd, unsigned char *buf, size_t len, uint32_t* crc) {
    datagen(buf, len, crc);
    if (write_data(fd, buf, len)) {
        pr_perror("can't write (pre)");
        return 1;
    }
    if (read_data(fd, buf, len)) {
        pr_perror("read less than have to (pre)");
        return 1;
    }
    if (datachk(buf, len, crc))
        return 2;
    return 0;
}

int main(int argc, char **argv)
{
	unsigned char buf[BUF_SIZE];
	int fd, fd_s;
	pid_t extpid;
	uint32_t crc;
	int real_port = 8880;
	char rule[256];

	if (unshare(CLONE_NEWNET)) {
		pr_perror("unshare");
		return 1;
	}
	if (system("ip link set up dev lo"))
		return 1;

	/*
	 * Bring the server up first so we know the real port to point the
	 * REDIRECT rule at. The connect()ing peer never sees this port -- it
	 * targets REDIR_PORT and the kernel DNATs.
	 */
	if ((fd_s = tcp_init_server(AF_INET, &real_port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	snprintf(rule, sizeof(rule),
		 "iptables -t nat -w -A OUTPUT -p tcp --dport %d "
		 "-j REDIRECT --to-ports %d", REDIR_PORT, real_port);
	if (system(rule))
		return 1;

	/*
	 * Force every packet through conntrack so the kernel populates an
	 * entry with IPS_DST_NAT set (and CTA_NAT_DST on dump). Without the
	 * DROP fallback, replies could bypass tracking on a hot path.
	 */
	if (system("iptables -w -A INPUT -i lo -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT"))
		return 1;
	if (system("iptables -w -A INPUT -j DROP"))
		return 1;

	test_init(argc, argv);

	extpid = fork();
	if (extpid < 0) {
		pr_perror("fork() failed");
		return 1;
	} else if (extpid == 0) {
		close(fd_s);

		fd = tcp_init_client(AF_INET, "127.0.0.1", REDIR_PORT);
		if (fd < 0)
			return 1;

        // Pre-migration round-trip: server -> client, client -> server.
        if (int ret = read_write_data(fd, buf, BUF_SIZE, &crc); ret) {
            pr_err("pre-migration data exchange failed: %d\n", ret);
            return 1;
        }

        // Post-migration round-trip: server -> client, client -> server.
        if (int ret = read_write_data(fd, buf, BUF_SIZE, &crc); ret) {
            pr_err("post-migration data exchange failed: %d\n", ret);
            return 1;
        }

		return 0;
	}

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

	if (int ret = write_read_data(fd, buf, BUF_SIZE, &crc); ret) {
        pr_err("pre-migration data exchange failed: %d\n", ret);
        return 1;
    }

	test_daemon();
	test_waitsig();

    if (int ret = write_read_data(fd, buf, BUF_SIZE, &crc); ret) {
        pr_err("post-migration data exchange failed: %d\n", ret);
        return 1;
    }

	pass();
	return 0;
}
