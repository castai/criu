/*
 * Shared-socket (multi-container) AF_UNIX stream/seqpacket support.
 *
 * See sk-unix-shared.h for the rationale. This file contains the parts
 * of the shared-socket feature that can be expressed without touching
 * internal sk-unix.c types (unix_sk_desc, unix_sk_info, UnixSkEntry).
 * That keeps the conflict surface with upstream localised to a handful
 * of thin call sites in sk-unix.c.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log.h"
#include "util-pie.h"
#include "xmalloc.h"

#include "sk-unix-shared.h"

#define UNIX_SHARED_RETRY_FLOOR_S	60
#define UNIX_SHARED_RETRY_CEILING_S	(24 * 60 * 60)
#define UNIX_SHARED_RETRY_SLEEP_US	(100 * 1000)

bool sk_shared_is_stream_ext_peer(int type)
{
	return type == SOCK_STREAM || type == SOCK_SEQPACKET;
}

char *sk_shared_getpeername_path(int inscope_fd, size_t *out_len)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	size_t path_len;
	char *buf;

	memset(&addr, 0, sizeof(addr));
	if (getpeername(inscope_fd, (struct sockaddr *)&addr, &len) < 0) {
		pr_debug("sk-unix-shared: getpeername on fd %d failed, errno=%d\n",
			 inscope_fd, errno);
		return NULL;
	}

	if (len <= sizeof(addr.sun_family) || addr.sun_path[0] == '\0') {
		/* Anonymous or abstract — nothing useful to record. */
		return NULL;
	}

	path_len = strnlen(addr.sun_path, sizeof(addr.sun_path));
	/*
	 * Allocate one extra byte and NUL-terminate so the buffer is
	 * also a valid C string. Callers currently use the length via
	 * out_len, but the terminator keeps the contract robust.
	 */
	buf = xmalloc(path_len + 1);
	if (!buf)
		return NULL;

	memcpy(buf, addr.sun_path, path_len);
	buf[path_len] = '\0';
	*out_len = path_len;
	return buf;
}

int sk_shared_connect_with_retry(int fd, const char *path, size_t path_len, int timeout_s)
{
	struct sockaddr_un addr;
	int tries, i;

	if (path_len == 0 || path_len > UNIX_PATH_MAX) {
		pr_err("sk-unix-shared: invalid external peer path length %zu\n", path_len);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, path_len);

	if (timeout_s < UNIX_SHARED_RETRY_FLOOR_S)
		timeout_s = UNIX_SHARED_RETRY_FLOOR_S;
	if (timeout_s > UNIX_SHARED_RETRY_CEILING_S)
		timeout_s = UNIX_SHARED_RETRY_CEILING_S;
	tries = timeout_s * (1000000 / UNIX_SHARED_RETRY_SLEEP_US);

	for (i = 0; i < tries; i++) {
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr.sun_family) + path_len) == 0) {
			pr_info("sk-unix-shared: reconnected to external peer %s after %d tries\n",
				addr.sun_path, i);
			return 0;
		}
		if (errno != ECONNREFUSED && errno != ENOENT) {
			pr_perror("sk-unix-shared: connect to external peer %s", addr.sun_path);
			return -1;
		}
		usleep(UNIX_SHARED_RETRY_SLEEP_US);
	}

	pr_err("sk-unix-shared: timed out reconnecting to external peer %s (%ds)\n",
	       addr.sun_path, timeout_s);
	return -1;
}

int sk_shared_dead_acceptor_fd(int type, int *out_fd)
{
	int sks[2];

	if (socketpair(PF_UNIX, type, 0, sks) < 0) {
		pr_perror("sk-unix-shared: can't make socketpair for dead acceptor");
		return -1;
	}

	/*
	 * Close the far end so the returned fd immediately sees EOF on
	 * read() and EPIPE on write(). The application is expected to
	 * handle this the same way it would handle a peer restart.
	 */
	close(sks[1]);
	*out_fd = sks[0];
	return 0;
}
