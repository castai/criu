/*
 * AIO ring helpers for live migration.
 *
 * When restoring on a system with more CPUs, the kernel may create larger
 * AIO rings. If the ring can't expand in place, we relocate it and patch
 * all memory references.
 *
 * This file is included directly into restorer.c to keep it in the same
 * translation unit (required for PIE code).
 */

/*
 * Calculate the page-aligned size of an AIO ring.
 */
static inline unsigned long live_aio_ring_size(unsigned int nr)
{
	unsigned long size = sizeof(struct aio_ring) + nr * sizeof(struct io_event);
	return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/*
 * Handle AIO ring expansion for live migration.
 *
 * When restoring on a system with more CPUs, the kernel creates larger rings.
 * This function decides whether to expand in place or relocate, and prepares
 * the address space accordingly.
 *
 * Returns: new ring length on success, 0 on failure
 */
static unsigned long live_handle_aio_expansion(struct rst_aio_ring *raio,
					       struct aio_ring *new,
					       unsigned long ctx)
{
	unsigned long new_ring_len = live_aio_ring_size(new->nr);

	if (new_ring_len > raio->max_len) {
		/*
		 * Cannot expand in place - will relocate ring to new location.
		 * The ring stays at ctx (where io_setup placed it).
		 */
		pr_info("AIO ring relocation: 0x%lx -> 0x%lx (no space)\n",
			raio->addr, ctx);
		raio->new_addr = ctx;
	} else if (new_ring_len > raio->len) {
		/*
		 * Expand in place: unmap extra area after original ring
		 * to make room for the larger ring.
		 */
		unsigned long extra = new_ring_len - raio->len;
		void *extra_addr = (void *)(raio->addr + raio->len);
		int ret;

		ret = sys_munmap(extra_addr, extra);
		if (ret < 0 && ret != -EINVAL) {
			pr_err("Cannot free space for AIO ring at %lx: %d\n",
			       raio->addr, ret);
			return 0;
		}
	}

	return new_ring_len;
}

/*
 * Finalize AIO ring placement.
 *
 * For non-relocated rings, moves the ring to its original address.
 * For relocated rings, the ring stays at the kernel-chosen location.
 *
 * Returns: 0 on success, -1 on failure
 */
static int live_finalize_aio_ring(struct rst_aio_ring *raio,
				  unsigned long ctx,
				  unsigned long ring_len)
{
	if (!raio->new_addr) {
		ctx = sys_mremap(ctx, ring_len, ring_len,
				 MREMAP_FIXED | MREMAP_MAYMOVE, raio->addr);
		if (ctx != raio->addr) {
			pr_err("Ring remap failed with %ld\n", ctx);
			return -1;
		}
	}
	return 0;
}

/*
 * Patch memory to update aio_context_t references after AIO ring relocation.
 * Scans writable VMAs for the old address and replaces with the new address.
 *
 * This is necessary because applications store the aio_context_t (ring address)
 * and use it for io_submit/io_getevents calls. If we relocate the ring, we need
 * to update these stored references.
 */
static int live_patch_aio_context_refs(struct task_restore_args *args,
				       unsigned long old_addr,
				       unsigned long new_addr)
{
	int i;
	int patched = 0;

	pr_info("Patching aio_context_t: 0x%lx -> 0x%lx\n", old_addr, new_addr);

	for (i = 0; i < args->vmas_n; i++) {
		VmaEntry *vma = &args->vmas[i];
		unsigned long addr;
		unsigned long *ptr;

		if (!(vma->prot & PROT_WRITE))
			continue;

		if (vma->status & VMA_AREA_AIORING)
			continue;

		if ((vma->status & VMA_AREA_VDSO) ||
		    (vma->status & VMA_AREA_VVAR) ||
		    (vma->status & VMA_AREA_VSYSCALL))
			continue;

		/*
		 * Scan this VMA for the old address value.
		 * Only check aligned positions (aio_context_t is unsigned long).
		 */
		for (addr = vma->start; addr + sizeof(unsigned long) <= vma->end;
		     addr += sizeof(unsigned long)) {
			ptr = (unsigned long *)addr;
			if (*ptr == old_addr) {
				pr_info("Patched aio_context_t at 0x%lx\n", addr);
				*ptr = new_addr;
				patched++;
			}
		}
	}

	if (patched == 0) {
		pr_warn("No aio_context_t references found to patch (old=0x%lx)\n",
			old_addr);
	} else {
		pr_info("Patched %d aio_context_t reference(s)\n", patched);
	}

	return 0;
}
