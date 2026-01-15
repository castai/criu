/*
 * AIO ring preparation with expansion support for live migration.
 *
 * When restoring on a system with more CPUs, the kernel may create larger
 * AIO rings. This file calculates how much space is available at each
 * ring's original address, allowing the restorer to expand in place when
 * possible (avoiding the need to relocate and patch memory references).
 *
 * This file is included directly into aio.c.
 */

/*
 * Calculate the maximum length available at an AIO ring's address.
 *
 * Looks at the VMA list to find how much contiguous free space exists
 * starting from the ring's address. This allows the restorer to know
 * if it can expand the ring in place or needs to relocate it.
 *
 * Returns the maximum length available (at least raio->len, potentially more).
 */
static unsigned long live_calc_aio_max_len(struct rst_aio_ring *raio,
					   struct vm_area_list *vmas)
{
	struct vma_area *vma;
	unsigned long ring_end = raio->addr + raio->len;
	unsigned long max_end;

	/*
	 * Start with a reasonable upper bound. We don't want to claim
	 * unlimited space even if nothing follows.
	 */
	max_end = raio->addr + (16 * 1024 * 1024); /* 16MB max */

	/*
	 * Find the first VMA that starts after our ring.
	 * The space between ring_end and that VMA's start is available.
	 */
	list_for_each_entry(vma, &vmas->h, list) {
		/* Skip VMAs that end before or at our ring's end */
		if (vma->e->end <= ring_end)
			continue;

		/* Skip the AIO ring VMA itself */
		if (vma->e->start == raio->addr)
			continue;

		/*
		 * This VMA starts after our ring. The available space
		 * is from ring start to this VMA's start.
		 */
		if (vma->e->start > raio->addr) {
			max_end = vma->e->start;
			break;
		}
	}

	return max_end - raio->addr;
}

/*
 * Prepare AIO ring info with expansion limits.
 *
 * For each AIO ring, calculate how much space is available at its
 * original address. This information is passed to the restorer which
 * uses it to decide whether to expand in place or relocate.
 */
static int live_prepare_aio_ring(struct rst_aio_ring *raio,
				 AioRingEntry *aio_entry,
				 struct vm_area_list *vmas)
{
	raio->new_addr = 0;

	/*
	 * Calculate how much space is available at the original address.
	 * This allows the restorer to expand the ring in place if the
	 * kernel creates a larger ring (due to more CPUs).
	 */
	raio->max_len = live_calc_aio_max_len(raio, vmas);

	pr_debug("AIO ring at 0x%lx: len=%lu, max_len=%lu\n",
		 raio->addr, raio->len, raio->max_len);

	return 0;
}
