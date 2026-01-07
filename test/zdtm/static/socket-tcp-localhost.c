/*
 * Test that localhost TCP connections are preserved across checkpoint/restore.
 *
 * With --tcp-close option, non-localhost TCP connections are closed,
 * but localhost connections should be fully restored and remain functional.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <string.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc = "Check that localhost TCP connections are preserved across C/R";
const char *test_author = "CAST AI";

static int port = 8880;

static int check_socket_connected(int sk, const char *name)
{
	struct {
		__u8 tcpi_state;
	} info;
	socklen_t len = sizeof(info);
	int err;

	err = getsockopt(sk, IPPROTO_TCP, TCP_INFO, (void *)&info, &len);
	if (err != 0) {
		pr_perror("Can't get %s socket state", name);
		return -1;
	}

	if (info.tcpi_state != TCP_ESTABLISHED) {
		pr_err("%s socket in wrong state (%i), expected ESTABLISHED (1)\n",
		       name, (int)info.tcpi_state);
		return -1;
	}

	return 0;
}

static int check_data_transfer(int server_sk, int client_sk)
{
	char send_buf[64] = "Hello from client after restore!";
	char recv_buf[64] = { 0 };
	char reply_buf[64] = "Hello from server after restore!";
	char reply_recv[64] = { 0 };
	int err;

	/* Client -> Server */
	err = send(client_sk, send_buf, sizeof(send_buf), 0);
	if (err != sizeof(send_buf)) {
		pr_perror("Failed to send data from client");
		return -1;
	}

	err = recv(server_sk, recv_buf, sizeof(recv_buf), 0);
	if (err != sizeof(send_buf)) {
		pr_perror("Failed to receive data on server");
		return -1;
	}

	if (memcmp(send_buf, recv_buf, sizeof(send_buf)) != 0) {
		pr_err("Client->Server data mismatch\n");
		return -1;
	}

	/* Server -> Client */
	err = send(server_sk, reply_buf, sizeof(reply_buf), 0);
	if (err != sizeof(reply_buf)) {
		pr_perror("Failed to send reply from server");
		return -1;
	}

	err = recv(client_sk, reply_recv, sizeof(reply_recv), 0);
	if (err != sizeof(reply_buf)) {
		pr_perror("Failed to receive reply on client");
		return -1;
	}

	if (memcmp(reply_buf, reply_recv, sizeof(reply_buf)) != 0) {
		pr_err("Server->Client data mismatch\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, fd_s, clt;
	char msg[] = "test before checkpoint";
	char buf[32] = { 0 };

	test_init(argc, argv);

	signal(SIGPIPE, SIG_IGN);

	fd_s = tcp_init_server(AF_INET, &port);
	if (fd_s < 0) {
		pr_err("Server initialization failed\n");
		return 1;
	}

	clt = tcp_init_client(AF_INET, "127.0.0.1", port);
	if (clt < 0) {
		pr_err("Client initialization failed\n");
		return 1;
	}

	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("Can't accept client connection\n");
		return 1;
	}

	/* Verify connection works before C/R */
	if (send(clt, msg, sizeof(msg), 0) != sizeof(msg)) {
		pr_perror("Pre-C/R send failed");
		return 1;
	}
	if (recv(fd, buf, sizeof(buf), 0) != sizeof(msg)) {
		pr_perror("Pre-C/R recv failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* After restore: verify sockets are still connected */
	if (check_socket_connected(fd, "server")) {
		fail("Server socket not connected after restore");
		return 1;
	}
	if (check_socket_connected(clt, "client")) {
		fail("Client socket not connected after restore");
		return 1;
	}

	/* Verify bidirectional data transfer still works */
	if (check_data_transfer(fd, clt)) {
		fail("Data transfer failed after restore");
		return 1;
	}

	close(clt);
	close(fd);
	close(fd_s);

	pass();
	return 0;
}
