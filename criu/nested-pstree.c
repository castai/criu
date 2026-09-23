#include <unistd.h>
#include <sched.h>
#include <errno.h>

#include "cr_options.h"
#include "pstree.h"
#include "rst_info.h"
#include "namespaces.h"
#include "nested-ns.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "net.h"
#include "util.h"

#include "images/userns.pb-c.h"

/*
 * The fixups of the process tree before it is forked, and the
 * namespaces the tasks of a nested user namespace create by
 * themselves. See nested-ns.h.
 */

/*
 * A task which has entered the namespaces of an inner container
 * without creating them (e.g. a docker exec-ed process) is restored
 * with the flags of the namespaces derived from the difference of its
 * ids from the ones of its parent task, so it would fork into its own
 * copies of them: siblings of the original ones, not enterable. It is
 * re-parented under the first task of the inner container instead
 * (the init one, which has created the namespaces): forked from it,
 * it inherits all of them, the same way as at dump.
 *
 * Known cost: the real parent of such a task (e.g. the shim of the
 * exec) loses it as a child, so an exec session in flight at the dump
 * time is terminated by the restore.
 */
static void fix_exec_pstree(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		struct pstree_item *parent = item->parent, *home;

		if (!parent || !item->ids)
			continue;

		/* Zombies and helpers can have ids == 0 so we skip them */
		while (parent && !parent->ids)
			parent = parent->parent;
		if (!parent)
			continue;

		/*
		 * The task is in the namespaces of its parent: nothing
		 * to fix, it inherits them with the fork.
		 */
		if (item->ids->pid_ns_id == parent->ids->pid_ns_id && item->ids->mnt_ns_id == parent->ids->mnt_ns_id &&
		    item->ids->user_ns_id == parent->ids->user_ns_id)
			continue;

		/*
		 * Find the home for the task: the first one in its
		 * mount namespace which is not a descendant of it (the
		 * init one of the inner container, normally).
		 */
		home = NULL;
		for_each_pstree_item(home) {
			struct pstree_item *p;

			if (home == item || !home->ids || !home->parent)
				continue;

			if (home->ids->mnt_ns_id != item->ids->mnt_ns_id ||
			    home->ids->pid_ns_id != item->ids->pid_ns_id ||
			    home->ids->user_ns_id != item->ids->user_ns_id || home->pid->state == TASK_DEAD)
				continue;

			/* not a descendant of item */
			for (p = home; p && p != item; p = p->parent)
				;
			if (!p)
				break;
		}
		if (!home || !home->ids || home == item)
			continue;

		pr_warn("Re-parenting the task %d from %d to %d: it has entered the namespaces of the latter at dump\n",
			vpid(item), vpid(parent), vpid(home));

		list_del(&item->sibling);
		item->parent = home;
		list_add_tail(&item->sibling, &home->children);
	}
}

void nested_ns_prepare_pstree(void)
{
	if (!nested_ns_enabled())
		return;

	fix_exec_pstree();
	nested_ns_mark_owned();
}

/*
 * The task which has created a nested user namespace at dump: the one
 * recorded in the image of the namespace, or, for the images without
 * it, the task with the lowest pid in the namespace.
 */
static struct pstree_item *userns_creator(unsigned int userns_id)
{
	struct pstree_item *item, *creator = NULL;
	UsernsEntry *e = NULL;
	pid_t creator_pid = 0;

	if (!nested_ns_read_userns_img(userns_id, &e)) {
		if (e->has_creator_pid)
			creator_pid = e->creator_pid;
		userns_entry__free_unpacked(e, NULL);
	}

	if (creator_pid) {
		creator = pstree_item_by_virt(creator_pid);
		if (creator && creator->ids && creator->ids->user_ns_id == userns_id)
			return creator;
		pr_warn("The recorded creator %d of the user namespace %u is not in it (%s, user ns %u)\n", creator_pid,
			userns_id, creator ? "found" : "not found", creator && creator->ids ? creator->ids->user_ns_id : 0);
		creator = NULL;
	}

	for_each_pstree_item(item) {
		if (!item->parent || !item->ids || item->ids->user_ns_id != userns_id)
			continue;
		if (!(rsti(item)->clone_flags & CLONE_NEWUSER))
			continue;
		if (!creator || vpid(item) < vpid(creator))
			creator = item;
	}

	return creator;
}

/*
 * Only the first task of each nested user namespace creates it at
 * restore: the others (the ones which have entered it at dump, e.g.
 * the docker exec-ed processes of an inner container) are forked
 * without CLONE_NEWUSER and join the created one instead (see
 * nested_ns_child_namespaces()).
 */
void nested_ns_fixup_clone_flags(void)
{
	struct pstree_item *item;

	if (!nested_ns_enabled())
		return;

	for_each_pstree_item(item) {
		struct pstree_item *creator;

		if (!item->parent || !nested_ns_task_nested(item))
			continue;

		if (!(rsti(item)->clone_flags & CLONE_NEWUSER))
			continue;

		creator = userns_creator(item->ids->user_ns_id);
		if (creator && creator != item) {
			pr_info("The task %d joins the user namespace created by %d\n", vpid(item), vpid(creator));
			rsti(item)->clone_flags &= ~CLONE_NEWUSER;
		}
	}
}

/*
 * Whether the network namespace is owned by a nested user namespace,
 * i.e. it is created by the task entering it (see
 * nested_ns_child_namespaces()), and not by the root task.
 */
bool nested_ns_own_netns(struct ns_id *nsid)
{
	return nsid && nsid->nd == &net_ns_desc && nested_ns_owned(nsid);
}

bool nested_ns_skip_netns(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;

	if (!nested_ns_task_nested(item) || !item->ids->has_net_ns_id)
		return false;

	/* Zombies and helpers can have ids == 0 so we skip them */
	while (parent && !parent->ids)
		parent = parent->parent;

	/*
	 * Our parent was born in the same net namespace, so we
	 * inherited it with fork() and there is no need to setns()
	 * into it. Besides, a task in a nested user namespace can
	 * not enter a namespace owned by a parent user namespace.
	 */
	return parent && item->ids->net_ns_id == parent->ids->net_ns_id;
}

/*
 * Restore the content of the namespaces owned by the nested user
 * namespace of this task: they are created empty at fork and are
 * filled in from their images here.
 */
int nested_ns_child_namespaces(struct pstree_item *item)
{
	struct ns_id *nsid;

	if (!nested_ns_enabled() || !item->parent)
		return 0;

	if (!(rsti(item)->clone_flags & CLONE_NEWUSER)) {
		/*
		 * A task forked from a one outside its user namespace (see
		 * nested_ns_fixup_clone_flags()): join the one created by
		 * the first task of it, so the namespaces owned by it are
		 * enterable. The ones forked from a task already in it
		 * have inherited the namespace with the fork: they are in
		 * it already, joining it is not allowed.
		 */
		struct pstree_item *parent = item->parent;

		while (parent && !parent->ids)
			parent = parent->parent;

		if (parent && nested_ns_task_nested(item) && item->ids->user_ns_id != parent->ids->user_ns_id)
			return nested_ns_join_userns(item);
	}

	/*
	 * The uts, ipc and cgroup namespaces below are the ones a task
	 * has unshared by itself, with or without a user namespace of its
	 * own: the classic restore never creates them for a sub-task.
	 */
	if (rsti(item)->clone_flags & CLONE_NEWUTS) {
		if (prepare_utsns(item->ids->uts_ns_id))
			return -1;
	}

	if (rsti(item)->clone_flags & CLONE_NEWIPC) {
		/*
		 * The IPC namespace created at our fork is empty:
		 * fill it in from its image, so the sysv shmem and
		 * semaphore segments of the inner container appear
		 * with their original ids in it, as the tasks forked
		 * by us mmap the former and use the latter.
		 */
		if (prepare_ipc_ns(item->ids->ipc_ns_id))
			return -1;
	}

	if (rsti(item)->clone_flags & CLONE_NEWCGROUP) {
		/*
		 * The cgroup namespace is not created at the fork of the
		 * task (see fork_with_pid): it is created here instead,
		 * after the task has been moved into the cgroup of the
		 * container, so the root of it is the same as the one at
		 * the dump time. The tasks forked by it inherit the
		 * namespace: they are members of it, like the ones of the
		 * other namespaces owned by our user namespace.
		 */
		if (unshare(CLONE_NEWCGROUP)) {
			pr_perror("Can't create the cgroup namespace");
			return -1;
		}
	}

	/*
	 * Make sure our /proc/self service fd cache is valid: the later
	 * restores (e.g. of a memfd shared with a sibling task) open
	 * /proc/self/fd/<fd>, and installing the service fd in the
	 * protected phase (sfds_protected) is not allowed.
	 */
	{
		int self_fd = open_proc(PROC_SELF, "ns/mnt");

		if (self_fd < 0)
			return -1;
		close(self_fd);
	}

	if ((rsti(item)->clone_flags & (CLONE_NEWUSER | CLONE_NEWNET)) == (CLONE_NEWUSER | CLONE_NEWNET)) {
		/*
		 * Create our own network namespace, which is owned by
		 * our user namespace, and fill it in from its image,
		 * as the ones created by the root task are owned by
		 * its user namespace. A network namespace of a task
		 * without a user namespace of its own is created and
		 * filled in by the root task, the classic way.
		 */
		nsid = lookup_ns_by_id(item->ids->net_ns_id, &net_ns_desc);
		if (!nsid) {
			pr_err("Can't find netns id %d\n", item->ids->net_ns_id);
			return -1;
		}

		if (nested_ns_child_netns(nsid))
			return -1;
	}

	return 0;
}
