#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

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
 * and fstatat ENOENT), creates link_remap.N on the source tmpfs, but never
 * stores the content.  On restore, link_remap.N does not exist on the
 * destination tmpfs -> ENOENT -> "Can't open vma".
 *
 * With the fix, CRIU detects TMPFS_MAGIC and falls back to dump_ghost_remap()
 * which embeds the content in the checkpoint image.
 */

#define FILE_SIZE	4096

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int fd;
	void *map;
	uint32_t crc_before, crc_after;
	struct stat st;
	char sempath[PATH_MAX];
	char anchorpath[PATH_MAX];

	test_init(argc, argv);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		pr_perror("mount tmpfs on %s", dirname);
		return 1;
	}

	snprintf(sempath, sizeof(sempath), "%s/sem.zdtm-link-remap-test", dirname);
	snprintf(anchorpath, sizeof(anchorpath), "%s/sem.zdtm-link-remap-anchor", dirname);

	/* Step 1: create the file on tmpfs. */
	fd = open(sempath, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_perror("open %s", sempath);
		goto umount;
	}
	if (ftruncate(fd, FILE_SIZE) < 0) {
		pr_perror("ftruncate");
		goto umount;
	}

	/* Step 2: mmap it MAP_SHARED -- creates the file-backed VMA. */
	map = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		pr_perror("mmap");
		goto umount;
	}

	/* Write known data and compute CRC before C/R. */
	crc_before = ~0;
	datagen(map, FILE_SIZE, &crc_before);

	/*
	 * Step 3: create a hard link so st_nlink becomes 2.
	 * This keeps the inode alive after we remove the original name,
	 * ensuring CRIU sees st_nlink=1 (not 0) and takes dump_linked_remap
	 * instead of dump_ghost_remap -- which is the bug trigger.
	 */
	if (link(sempath, anchorpath) < 0) {
		pr_perror("link");
		goto umount;
	}

	/*
	 * Step 4: unlink the mapped name.
	 * st_nlink drops to 1 (anchor survives).
	 * /proc/PID/maps now shows the file as "(deleted)".
	 * fstatat on that path returns ENOENT.
	 * CRIU without fix: st_nlink=1 + ENOENT -> dump_linked_remap -> fails.
	 * CRIU with fix:    TMPFS_MAGIC detected -> dump_ghost_remap -> works.
	 */
	if (unlink(sempath) < 0) {
		pr_perror("unlink");
		goto umount;
	}

	/* Verify the trigger state: st_nlink=1, mapped path gone. */
	if (fstat(fd, &st) < 0) {
		pr_perror("fstat");
		goto umount;
	}
	if (st.st_nlink != 1) {
		fail("Expected st_nlink=1, got %lu", (unsigned long)st.st_nlink);
		goto umount;
	}

	test_daemon();
	test_waitsig();

	/* After C/R: verify the mmap content is intact. */
	crc_after = ~0;
	if (datachk(map, FILE_SIZE, &crc_after)) {
		fail("mmap content CRC mismatch after restore");
		goto cleanup;
	}

	/* Verify the fd is still usable. */
	if (fstat(fd, &st) < 0) {
		pr_perror("fstat after restore");
		goto cleanup;
	}
	if (st.st_size != FILE_SIZE) {
		fail("fd size changed: expected %d got %lld",
		     FILE_SIZE, (long long)st.st_size);
		goto cleanup;
	}

	pass();
cleanup:
	munmap(map, FILE_SIZE);
	close(fd);
	unlink(anchorpath);
umount:
	umount2(dirname, MNT_DETACH);
	return 0;
}
