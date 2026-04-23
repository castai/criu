#ifndef __CR_SK_UNIX_SHARED_H__
#define __CR_SK_UNIX_SHARED_H__

#include <stddef.h>

/*
 * Support for AF_UNIX stream/seqpacket sockets that cross a
 * checkpoint-scope boundary (e.g., two containers in the same pod
 * sharing a unix socket via a volume).
 *
 * The logic lives in sk-unix-shared.c to keep the conflict surface in
 * sk-unix.c (which tracks upstream closely) as small as possible. The
 * functions here intentionally take only primitive types — no
 * dependency on unix_sk_desc / unix_sk_info / UnixSkEntry layout — so
 * the implementation can evolve independently of internal sk-unix
 * refactors.
 */

/*
 * Recover the path of a connected unix socket's peer via getpeername().
 *
 * Used at dump time on the in-scope (client-side) fd of an external
 * peer to learn the listener's bound path, which we store on the
 * external stub so restore can reconnect.
 *
 * On a server-side accepted fd, the peer is nameless and this returns
 * NULL (success) with *out_len left unchanged.
 *
 * Returns:
 *   malloc'd buffer + length via *out_len on success (caller must
 *     xfree), OR
 *   NULL if the peer is nameless/abstract/getpeername fails — the
 *     dump path keeps the stub nameless in that case.
 *
 * inscope_fd should be a dup of the live fd valid while the process
 * is frozen.
 */
char *sk_shared_getpeername_path(int inscope_fd, size_t *out_len);

/*
 * Connect a unix stream socket to the given path, retrying while the
 * peer listener is not yet up (ECONNREFUSED / ENOENT).
 *
 * Used at restore time on the connector-side to reach an external
 * listener that may belong to a sibling container whose restore is
 * still in progress.
 *
 * Retries for max(timeout_s, 60) seconds in 100ms increments. Errors
 * other than ECONNREFUSED / ENOENT fail immediately.
 *
 * Returns 0 on success, -1 on failure (caller owns the fd either way;
 * close on failure).
 */
int sk_shared_connect_with_retry(int fd, const char *path, size_t path_len, int timeout_s);

/*
 * Allocate a "dead" unix fd: a socketpair with the far end closed.
 * The returned fd is a valid AF_UNIX stream/seqpacket fd; read() will
 * immediately return 0 (EOF), write() will raise EPIPE.
 *
 * Used at restore time on the acceptor-side (server's originally
 * accept()'d fd for an external client). The application's accept
 * loop picks up fresh connections from the restored listener; the old
 * connection is intentionally broken.
 *
 * type is SOCK_STREAM or SOCK_SEQPACKET.
 *
 * Returns 0 on success with *out_fd set, -1 on failure.
 */
int sk_shared_dead_acceptor_fd(int type, int *out_fd);

#endif /* __CR_SK_UNIX_SHARED_H__ */
