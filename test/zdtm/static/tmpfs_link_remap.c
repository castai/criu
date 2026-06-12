#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that a tmpfs file with st_nlink>=1 but "
			  "mapped-path ENOENT (POSIX semaphore pattern) "
			  "is correctly checkpointed and restored";
const char *test_author = "Filipe Augusto Lima de Souza <filipe@cast.ai>";

/*
 * Reproduces the state created by Python multiprocessing on Linux (fork
 * context): sem_open() creates /dev/shm/sem.NAME (st_nlink=1), mmaps it
 * internally, then sem_unlink() removes the name while another hard link
 * keeps st_nlink=1.
 *
 * Without the fix, CRIU dump takes dump_linked_remap() (because st_nlink>=1
 * and fstatat ENOENT), creates link_remap.N on the source /dev/shm tmpfs,
 * but never stores the content.  On restore, link_remap.N does not exist on
 * the destination tmpfs -> ENOENT -> "Can't open vma".
 *
 * With the fix, CRIU detects TMPFS_MAGIC and falls back to dump_ghost_remap()
 * which embeds the content in the checkpoint image.
 */

#define SHM_DIR		"/dev/shm"
#define SEM_NAME	SHM_DIR "/sem.zdtm-link-remap-test"
#define SEM_ANCHOR	SHM_DIR "/sem.zdtm-link-remap-anchor"
#define SEM_SIZE	4096

int main(int argc, char **argv)
{
	int fd;
	void *map;
	uint32_t crc_before, crc_after;
	struct stat st;

	test_init(argc, argv);

	/* Clean up any leftovers. */
	unlink(SEM_NAME);
	unlink(SEM_ANCHOR);

	/* Step 1: create the file on tmpfs. */
	fd = open(SEM_NAME, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}
	if (ftruncate(fd, SEM_SIZE) < 0) {
		pr_perror("ftruncate");
		return 1;
	}

	/* Step 2: mmap it MAP_SHARED -- creates the file-backed VMA. */
	map = mmap(NULL, SEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	/* Write known data and compute CRC before C/R. */
	crc_before = ~0;
	datagen(map, SEM_SIZE, &crc_before);

	/*
	 * Step 3: create a hard link so st_nlink becomes 2.
	 * This keeps the inode alive after we remove the original name,
	 * ensuring CRIU sees st_nlink=1 (not 0) and takes dump_linked_remap
	 * instead of dump_ghost_remap -- which is the bug trigger.
	 */
	if (link(SEM_NAME, SEM_ANCHOR) < 0) {
		pr_perror("link");
		return 1;
	}

	/*
	 * Step 4: unlink the mapped name.
	 * st_nlink drops to 1 (anchor survives).
	 * /proc/PID/maps now shows "sem.zdtm-link-remap-test (deleted)".
	 * fstatat on that path returns ENOENT.
	 * CRIU without fix: st_nlink=1 + ENOENT -> dump_linked_remap -> restore fails.
	 * CRIU with fix:    TMPFS_MAGIC detected -> dump_ghost_remap -> restore works.
	 */
	if (unlink(SEM_NAME) < 0) {
		pr_perror("unlink");
		return 1;
	}

	/* Verify the trigger state: st_nlink=1, mapped path gone. */
	if (fstat(fd, &st) < 0) {
		pr_perror("fstat");
		return 1;
	}
	if (st.st_nlink != 1) {
		fail("Expected st_nlink=1, got %lu", (unsigned long)st.st_nlink);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* After C/R: verify the mmap content is intact. */
	crc_after = ~0;
	if (datachk(map, SEM_SIZE, &crc_after)) {
		fail("mmap content CRC mismatch after restore");
		goto out;
	}

	/* Verify the fd is still usable. */
	if (fstat(fd, &st) < 0) {
		pr_perror("fstat after restore");
		goto out;
	}
	if (st.st_size != SEM_SIZE) {
		fail("fd size changed: expected %d got %lld",
		     SEM_SIZE, (long long)st.st_size);
		goto out;
	}

	pass();
out:
	munmap(map, SEM_SIZE);
	close(fd);
	unlink(SEM_ANCHOR); /* clean up anchor */
	return 0;
}
