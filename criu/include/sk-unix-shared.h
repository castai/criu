#ifndef __CR_SK_UNIX_SHARED_H__
#define __CR_SK_UNIX_SHARED_H__

#include <stdbool.h>
#include <stddef.h>

/*
 * Primitive helpers for the shared-socket (multi-container AF_UNIX)
 * support added in this fork.
 *
 * The helpers here take only primitive types. The sk-unix.c alternative
 * code paths that glue these to the internal unix_sk_desc /
 * unix_sk_info / UnixSkEntry layouts live alongside the upstream
 * functions they supplement, as static sk_shared_* functions — this
 * keeps upstream bodies untouched and confines layout dependencies to
 * sk-unix.c, where struct definitions are anyway already private.
 */

/*
 * True if the external peer type warrants the shared-socket alternative
 * path: SOCK_STREAM or SOCK_SEQPACKET. SOCK_DGRAM still uses the
 * upstream --ext-unix-sk flow.
 */
bool sk_shared_is_stream_ext_peer(int type);

/*
 * Recover the path of a connected unix socket's peer via getpeername().
 *
 * Used at dump time on the in-scope (client-side) fd of an external
 * peer to learn the listener's bound path, which we store on the
 * external stub so restore can reconnect.
 *
 * On a server-side accepted fd, the peer is nameless and this returns
 * NULL with *out_len untouched.
 *
 * Returns a malloc'd buffer (caller xfree's) + length via *out_len on
 * success, or NULL if the peer is nameless/abstract/getpeername fails.
 *
 * inscope_fd should be a dup of the live fd valid while the process
 * is frozen.
 */
char *sk_shared_getpeername_path(int inscope_fd, size_t *out_len);

/*
 * Connect a unix stream socket to the given path, retrying while the
 * peer listener is not yet up (ECONNREFUSED / ENOENT).
 *
 * Retries for max(timeout_s, 60) seconds in 100ms increments. Errors
 * other than ECONNREFUSED / ENOENT fail immediately.
 *
 * Returns 0 on success, -1 on failure (caller owns fd either way).
 */
int sk_shared_connect_with_retry(int fd, const char *path, size_t path_len, int timeout_s);

/*
 * Allocate a "dead" unix fd: a socketpair with the far end closed.
 * Read on the returned fd returns 0 (EOF); write raises EPIPE.
 *
 * Used at restore time on the acceptor-side: the application's accept
 * loop picks up fresh connections from the restored listener, the old
 * connection is intentionally broken.
 *
 * type is SOCK_STREAM or SOCK_SEQPACKET.
 *
 * Returns 0 on success with *out_fd set, -1 on failure.
 */
int sk_shared_dead_acceptor_fd(int type, int *out_fd);

#endif /* __CR_SK_UNIX_SHARED_H__ */
