#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "Stress vmsplice short-return path with a large anonymous map";
const char *test_author = "Filipe Brandenburger <filbranden@google.com>";

#define ALLOC_SIZE (256 * 1024 * 1024)

struct page_header {
	unsigned long index;
	unsigned long checksum;
};

int main(int argc, char **argv)
{
	void *mem;
	unsigned long nr_pages, i, fail_idx = 0;
	int ret = 0;

	test_init(argc, argv);

	mem = mmap(NULL, ALLOC_SIZE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("mmap failed");
		return 1;
	}

	nr_pages = ALLOC_SIZE / PAGE_SIZE;

	test_msg("mem %p nr_pages %lu\n", mem, nr_pages);

	/* Touch every page and fill it with a per-page pattern that
	 * detects both content corruption and page reordering.
	 */
	for (i = 0; i < nr_pages; i++) {
		char *page = (char *)mem + i * PAGE_SIZE;
		struct page_header *hdr = (struct page_header *)page;
		unsigned char fill = (unsigned char)(i & 0xff);
		size_t tail = PAGE_SIZE - sizeof(struct page_header);

		hdr->index = i;
		hdr->checksum = ~i;
		memset(page + sizeof(struct page_header), fill, tail);
	}

	test_daemon();
	test_waitsig();

	test_msg("verifying %lu pages\n", nr_pages);
	for (i = 0; i < nr_pages; i++) {
		char *page = (char *)mem + i * PAGE_SIZE;
		struct page_header *hdr = (struct page_header *)page;
		unsigned char fill = (unsigned char)(i & 0xff);
		size_t tail = PAGE_SIZE - sizeof(struct page_header);
		char *buf = page + sizeof(struct page_header);

		if (hdr->index != i || hdr->checksum != ~i) {
			fail_idx = i;
			fail("page %lu header mismatch: index=%lu checksum=%lu",
			     i, hdr->index, hdr->checksum);
			ret = 1;
			break;
		}

		/* Verify the rest of the page is filled with the expected byte. */
		if (buf[0] != (char)fill || buf[tail - 1] != (char)fill ||
		    memchr(buf, (int)(unsigned char)(fill ^ 0xff), tail) != NULL) {
			fail_idx = i;
			fail("page %lu pattern mismatch, expected fill 0x%02x",
			     i, fill);
			ret = 1;
			break;
		}
	}

	if (ret == 0)
		pass();
	else
		test_msg("first failed page: %lu\n", fail_idx);

	munmap(mem, ALLOC_SIZE);
	return ret;
}
