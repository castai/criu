/*
 * Live-migration inotify/fanotify watch handling.
 *
 * Upstream CRIU fails the whole dump when a watch target has no
 * resolvable path, and drops ghost-file watches at restore when the
 * ghost name is unlinked. Both are wrong for live migration:
 *
 *  - A watch with no path is only dumpable when its target was dumped
 *    as a ghost file (deleted while still open) — anything else is a
 *    resolution bug that must fail loudly instead of silently losing
 *    the watch. The decision needs the ghost registry, which is only
 *    complete after every file of every task has been dumped, so the
 *    watch is deferred to fsnotify_resolve_pending().
 *
 *  - At restore, the ghost-file remap re-arms the watch on the
 *    re-created ghost file, and the restorer unlinks the ghost name
 *    twice afterwards. Either unlink can run fsnotify_inoderemove()
 *    on the inode and IN_IGNORED the just-armed watch: the restored
 *    task keeps writing to an fd whose watch no longer fires. The
 *    target fd is pinned above the task's fd range so the ghost
 *    dentry survives both unlinks; FD_CLOEXEC releases it at the
 *    final exec, after every ghost unlink has happened.
 *
 * Also here: the irmap scan-root coverage test. A file with
 * st_dev == dev lives only inside mounts of that device, so a scan
 * root can reach the watch only when the mount the root sits in is
 * of that device, or when a mount of the device hangs below the
 * root. Roots that cover nothing are skipped before any walk: a path
 * list that includes an unrelated or network mount cannot stall the
 * dump on trees the watch cannot be in anyway.
 *
 * This file is included directly into fsnotify.c. The irmap hook
 * (live_irmap_root_covers_dev) is included into irmap.c from
 * live_irmap.c.
 */

static LIST_HEAD(pending_watches);

struct pending_watch {
	struct list_head list;
	u32 s_dev;
	u64 i_ino;
};

static int add_pending_watch(u32 s_dev, u64 i_ino)
{
	struct pending_watch *p = xmalloc(sizeof(*p));

	if (!p)
		return -1;
	p->s_dev = s_dev;
	p->i_ino = i_ino;
	list_add_tail(&p->list, &pending_watches);
	return 0;
}

/*
 * Decide the fate of the watches no resolution path could map. Must run
 * after every file of every task has been dumped, so the ghost registry
 * is complete. In the final dump a watch may stay pathless only when
 * its target was dumped as a ghost file; a live target that nothing
 * could map is a resolution bug and fails the dump instead of
 * silently dropping the watch. Pre-dump writes no ghost files, so
 * there the deferred list is only drained: the final dump decides.
 */
int fsnotify_resolve_pending(int strict)
{
	struct pending_watch *p, *n;

	list_for_each_entry_safe(p, n, &pending_watches, list) {
		if (lookup_ghost_remap(p->s_dev, p->i_ino)) {
			pr_info("watch 0x%x:0x%lx target dumped as ghost file, restore will re-attach\n",
				p->s_dev, p->i_ino);
		} else if (strict) {
			pr_err("watch 0x%x:0x%lx target is live but has no resolved path\n",
				p->s_dev, p->i_ino);
			return -1;
		} else {
			pr_warn("watch 0x%x:0x%lx unresolved in pre-dump\n", p->s_dev, p->i_ino);
		}
		list_del(&p->list);
		xfree(p);
	}
	return 0;
}

/*
 * Pin the remap target fd above the task's fd range. The fd holds the
 * ghost file's dentry through the restorer's unlinks of the ghost
 * name (open_path() and try_clean_remaps()), so the kernel cannot run
 * fsnotify_inoderemove() on the inode and IN_IGNORED the just-armed
 * watch. It must not occupy a slot the task's own fd table restoration
 * wants. FD_CLOEXEC closes it at the final exec, after every ghost
 * unlink has happened — the task's own restored fd keeps the inode
 * alive from there on.
 */
static int live_fsnotify_pin_remap_fd(int *target)
{
	int pin = fcntl(*target, F_DUPFD, 1024);

	if (pin < 0) {
		pr_perror("Can't pin ghost watch fd");
		return -1;
	}
	close(*target);
	fcntl(pin, F_SETFD, FD_CLOEXEC);
	*target = pin;
	return 0;
}

/*
 * A restored watch with no path and no remap points at a target that is
 * gone: the watch entry was dumped without a path because the target
 * was deleted, and the ghost remap did not claim it. Dropping one
 * watch beats failing the restore of everything else;
 * INOTIFY_IOC_SETNEXTWD keeps the wd numbering of the remaining
 * watches exact across the gap.
 */
static bool live_fsnotify_mark_gone(FhEntry *f_handle, struct file_remap *remap)
{
	return !f_handle->path && !remap;
}
