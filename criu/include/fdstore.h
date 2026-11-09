#ifndef __CRIU_FDSTORE_H__
#define __CRIU_FDSTORE_H__

/*
 * fdstore is a storage for file descriptors which is shared
 * between processes.
 */

int fdstore_init(void);

/* Add a file descriptor to the storage and return its id */
int fdstore_add(int fd);

/* Get a file descriptor from a storage by id */
int fdstore_get(int id);

/*
 * Add a file descriptor to the storage under a key. The keys live in
 * the shared memory of the restore, so the ones added by a task are
 * visible to the others; a key added twice is not detected (the first
 * one wins).
 */
int fdstore_add_key(const char *key, int fd);

/* Get a file descriptor from a storage by key, -1 if the key is not there yet */
int fdstore_get_key(const char *key);

#endif
