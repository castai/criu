#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/nsfs.h>

#ifndef NS_GET_USERNS
#define NS_GET_USERNS _IO(NSIO, 0x1)
#endif
#ifndef NS_GET_PARENT
#define NS_GET_PARENT _IO(NSIO, 0x2)
#endif

#include "cr_options.h"
#include "kerndat.h"
#include "pstree.h"
#include "rst_info.h"
#include "namespaces.h"
#include "nested-ns.h"
#include "mount.h"
#include "net.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "cgroup.h"
#include "proc_parse.h"
#include "util.h"

/*
 * The option, the ownership marks and the pid arithmetic of the
 * nested pid namespaces. See nested-ns.h for the layout of the files.
 */

bool nested_ns_enabled(void)
{
	return opts.nested_ns;
}

bool nested_ns_owned(struct ns_id *nsid)
{
	return nested_ns_enabled() && nsid && nsid->nested;
}

bool nested_ns_task_nested(struct pstree_item *item)
{
	if (!nested_ns_enabled() || !item || !item->ids || !root_item || !root_item->ids)
		return false;

	return item->ids->user_ns_id != root_item->ids->user_ns_id;
}

bool nested_ns_real_pid_nested(pid_t real)
{
	if (!nested_ns_enabled())
		return false;

	return nested_ns_task_nested(pstree_item_by_real(real));
}

static bool task_in_nested_pidns(struct pstree_item *item)
{
	return item->ids && root_item->ids && item->ids->pid_ns_id != root_item->ids->pid_ns_id;
}

/*
 * Mark the namespaces of a task living in a nested user namespace as
 * owned by it: the ones which differ from the root task's ones. Used
 * on both dump (after the task ids are collected) and restore (after
 * the tree is read), the ns_id-s of both sides are looked up by id.
 */
static void mark_one(unsigned int id, unsigned int root_id, struct ns_desc *nd)
{
	struct ns_id *ns;

	if (!id || id == root_id)
		return;

	ns = lookup_ns_by_id(id, nd);
	if (ns && !ns->nested) {
		ns->nested = true;
		pr_debug("The %s namespace %u is owned by a nested user namespace\n", nd->str, id);
	}
}

static void mark_task_namespaces(struct pstree_item *item)
{
	TaskKobjIdsEntry *i = item->ids, *r = root_item->ids;

	mark_one(i->user_ns_id, r->user_ns_id, &user_ns_desc);
	if (i->has_mnt_ns_id)
		mark_one(i->mnt_ns_id, r->mnt_ns_id, &mnt_ns_desc);
	if (i->has_net_ns_id)
		mark_one(i->net_ns_id, r->net_ns_id, &net_ns_desc);
	if (i->has_uts_ns_id)
		mark_one(i->uts_ns_id, r->uts_ns_id, &uts_ns_desc);
	if (i->has_ipc_ns_id)
		mark_one(i->ipc_ns_id, r->ipc_ns_id, &ipc_ns_desc);
	if (i->has_pid_ns_id)
		mark_one(i->pid_ns_id, r->pid_ns_id, &pid_ns_desc);
	if (i->has_cgroup_ns_id)
		mark_one(i->cgroup_ns_id, r->cgroup_ns_id, &cgroup_ns_desc);
}

void nested_ns_mark_owned(void)
{
	struct pstree_item *item;

	if (!nested_ns_enabled() || !root_item->ids)
		return;

	for_each_pstree_item(item) {
		if (nested_ns_task_nested(item))
			mark_task_namespaces(item);
	}
}

/*
 * Dump side
 */

bool nested_ns_dump_ok(struct ns_desc *nd)
{
	/*
	 * User, uts, net, pid, ipc and cgroup namespaces may be
	 * nested (e.g. for a docker-in-docker container). A nested
	 * cgroup namespace is taken into the image, but it is not
	 * re-created on restore: its processes run in the one of
	 * their parent task. All the other ones keep failing with
	 * the usual error.
	 */
	return nested_ns_enabled() &&
	       (nd == &user_ns_desc || nd == &uts_ns_desc || nd == &net_ns_desc || nd == &pid_ns_desc ||
		nd == &ipc_ns_desc || nd == &cgroup_ns_desc);
}

/*
 * The pid of a task forked by a one living in a nested user namespace
 * can be restored only if the pid namespace it lives in is owned by
 * that user namespace: the parent task has no capabilities in the
 * ancestor ones (see nested_ns_pid_can_not_be_set()). Warn about the
 * tasks which will be restored with a random pid.
 */
static int check_pid_restorable(struct pstree_item *item, struct pstree_item *parent)
{
	struct ns_id *uns;
	struct stat st;
	int fd, ufd;

	if (item->ids->pid_ns_id != parent->ids->pid_ns_id)
		return 0;

	uns = lookup_ns_by_id(parent->ids->user_ns_id, &user_ns_desc);
	if (!uns)
		return 0;

	fd = open_proc(item->pid->real, "ns/pid");
	if (fd < 0)
		return -1;

	ufd = ioctl(fd, NS_GET_USERNS);
	close(fd);
	if (ufd < 0) {
		pr_perror("Can't get the owner of the pid namespace of %d", item->pid->real);
		return -1;
	}

	if (fstat(ufd, &st)) {
		pr_perror("Can't stat the owner of the pid namespace of %d", item->pid->real);
		close(ufd);
		return -1;
	}
	close(ufd);

	if (st.st_ino != uns->kid)
		pr_warn("The pid namespace of %d is not owned by the user namespace of its parent: it will be restored with a random pid\n",
			item->pid->real);

	return 0;
}

/*
 * On restore a user namespace is recreated when the parent task
 * forks a task living in it, so its uid and gid mappings have to be
 * relative to the user namespace of the parent task. Check that
 * they really are a child of it, and not of any other user
 * namespace, and that the parent task lives in the user namespace
 * of the root task: the id translations only cover one level.
 */
static int check_nested_user_ns(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct ns_id *ns, *pns;
	struct stat st;
	int fd, pfd;

	while (parent && !parent->ids)
		parent = parent->parent;

	if (!parent) {
		pr_err("Can't find a parent task with ids for %d\n", item->pid->real);
		return -1;
	}

	if (item->ids->user_ns_id == parent->ids->user_ns_id) {
		/*
		 * A task below the one which has entered the nested
		 * user namespace. It inherits the network and mount
		 * namespaces from it, as the ones created for it on
		 * restore would be owned by the nested user namespace
		 * and are not supported yet.
		 */
		if (item->ids->net_ns_id != parent->ids->net_ns_id || item->ids->mnt_ns_id != parent->ids->mnt_ns_id) {
			pr_err("Can't dump a task in a nested user namespace with its own net or mount namespace below the one entering it (pid %d)\n",
			       item->pid->real);
			return -1;
		}
		return check_pid_restorable(item, parent);
	}

	if (parent->ids->user_ns_id != root_item->ids->user_ns_id) {
		pr_err("Only one level of nested user namespaces is supported: the parent %d of %d lives in a nested one itself\n",
		       parent->pid->real, item->pid->real);
		return -1;
	}

	/*
	 * The task which enters the nested user namespace may have
	 * its own pid, network and mount namespaces, which are created
	 * by it on restore. The time namespace is not supported yet.
	 */
	if (item->ids->has_time_ns_id != parent->ids->has_time_ns_id ||
	    (item->ids->has_time_ns_id && item->ids->time_ns_id != parent->ids->time_ns_id)) {
		pr_err("Can't dump a task in a nested user namespace with its own time namespace (pid %d)\n",
		       item->pid->real);
		return -1;
	}

	ns = lookup_ns_by_id(item->ids->user_ns_id, &user_ns_desc);
	pns = lookup_ns_by_id(parent->ids->user_ns_id, &user_ns_desc);
	if (!ns || !pns) {
		pr_err("Can't find user namespace ids for %d\n", item->pid->real);
		return -1;
	}

	fd = open_proc(item->pid->real, "ns/user");
	if (fd < 0)
		return -1;

	pfd = ioctl(fd, NS_GET_PARENT);
	if (pfd < 0) {
		pr_perror("Can't get the parent user namespace of %d", item->pid->real);
		close(fd);
		return -1;
	}

	if (fstat(pfd, &st)) {
		pr_perror("Can't stat the parent user namespace of %d", item->pid->real);
		close(pfd);
		close(fd);
		return -1;
	}
	close(pfd);
	close(fd);

	if (st.st_ino != pns->kid) {
		pr_err("The user namespace of %d is not a child of the user namespace of its parent task\n",
		       item->pid->real);
		return -1;
	}

	return 0;
}

/*
 * A task which has entered a nested user namespace without creating
 * it (its parent task lives outside of it, and the namespace was
 * created by another task: the first one met in the walk of the
 * tree, parents before children) is restored as a child of the
 * creator, so it inherits the namespaces (see
 * nested_ns_prepare_pstree()). Its parent of the dump time loses it:
 * announce it.
 */
static void check_entered_task(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct ns_id *uns;

	while (parent && !parent->ids)
		parent = parent->parent;
	if (!parent || parent->ids->user_ns_id == item->ids->user_ns_id)
		return;

	uns = lookup_ns_by_id(item->ids->user_ns_id, &user_ns_desc);
	if (!uns || uns->ns_pid == item->pid->real)
		return;

	pr_warn("The task %d has entered the user namespace created by %d: it is restored as a child of that task, its parent %d loses it\n",
		item->pid->real, uns->ns_pid, parent->pid->real);
}

int nested_ns_check_task(struct pstree_item *item)
{
	if (!nested_ns_enabled() || !item->parent)
		return 0;

	if (nested_ns_task_nested(item)) {
		if (check_nested_user_ns(item))
			return -1;
		mark_task_namespaces(item);
		check_entered_task(item);
	}

	return 0;
}

pid_t nested_ns_dump_vpid(pid_t real, pid_t fallback)
{
	if (!nested_ns_enabled())
		return fallback;

	/*
	 * A negative return means the task is not a member of the pid
	 * namespace of the root task: the callers refuse the dump (a
	 * wrong-level pid in the image would break the restore).
	 */
	return pid_at_dump_level(real, fallback);
}

/*
 * The sid and the pgid from the parasite are in the pid namespace of
 * the task. Translate them into the one of the root task, the same
 * way as the pid itself.
 */
int nested_ns_dump_session(pid_t real, int *pgid, int *sid)
{
	int ret;

	if (!nested_ns_enabled())
		return 0;

	ret = parse_pid_session(real, pgid, sid);
	if (ret < 0) {
		pr_err("Can't read the session of %d\n", real);
		return -1;
	}
	if (ret > 0)
		/*
		 * The session or the group leader is not visible anymore
		 * (it exited and was reaped, e.g. the exec-ed shell of a
		 * runtime exec): the ids of the task itself (the ones of
		 * its own pid namespace, reported by the parasite) are
		 * kept, they are left untouched by this call.
		 */
		return 0;

	return 0;
}

pid_t nested_ns_dump_own_pid(pid_t real, pid_t fallback)
{
	if (!nested_ns_enabled())
		return fallback;

	return pid_at_own_level(real, fallback);
}

/*
 * Restore side
 */

/*
 * The tasks of the inner containers are forked with random pids in the
 * root pid namespace: their parents live in a nested user namespace,
 * which has no capabilities to set them (see
 * nested_ns_pid_can_not_be_set). The kernel assigns the random ones
 * from the pid counter of the namespace, which the earlier forks of
 * the tasks with the requested ones leave just below those, so a
 * random one can collide with the next requested one: the fork of it
 * fails with EEXIST and the restore with it. Move the counter above
 * every requested pid before any task is forked: the random ones are
 * taken from above them all.
 */
int nested_ns_seed_pid_counter(void)
{
	char buf[32];
	unsigned long max = 0;
	struct pstree_item *item;
	int fd, len;

	if (!nested_ns_enabled())
		return 0;

	/* The highest pid requested by any task of the tree. */
	for_each_pstree_item(item) {
		if (vpid(item) > (pid_t)max)
			max = vpid(item);
		if (item->own_ns_pid > (pid_t)max)
			max = item->own_ns_pid;
	}

	len = snprintf(buf, sizeof(buf), "%lu", max + 1000);

	fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open the pid namespace counter");
		return -1;
	}

	if (write(fd, buf, len) != len) {
		pr_perror("Can't seed the pid namespace counter to %s", buf);
		close(fd);
		return -1;
	}
	close(fd);

	pr_debug("Seeded the pid namespace counter above %lu\n", max);
	return 0;
}

int nested_ns_check_restore(bool image_nested_ns, bool has_image_flag)
{
	if (has_image_flag && image_nested_ns && !nested_ns_enabled()) {
		pr_err("The images were dumped with --nested-ns: the restore needs it too\n");
		return -1;
	}

	if (nested_ns_enabled() && !kdat.has_clone3_set_tid) {
		pr_err("--nested-ns needs clone3() with set_tid (a 5.5+ kernel)\n");
		return -1;
	}

	return 0;
}

bool nested_ns_cflags_ok(unsigned long cflags)
{
	if (!nested_ns_enabled())
		return false;

	/*
	 * In addition to the nested CLONE_SUBNS namespaces a sub-task
	 * may be created in its own user namespace and, from inside
	 * it, in its own uts, net, pid, ipc and cgroup ones, which are
	 * restored when its parent task forks it.
	 */
	return !((cflags & ~(root_ns_mask & CLONE_SUBNS)) &
		 ~(CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWCGROUP));
}

/*
 * The user namespace owning the pid namespace of a task: the one the
 * creator of the pid namespace (the task forked with CLONE_NEWPID into
 * it) lives in, or the one of the criu process for the pid namespace
 * criu itself runs in.
 */
static unsigned int pidns_owner_userns(struct pstree_item *task)
{
	struct pstree_item *c;

	for (c = task; c; c = c->parent) {
		if ((rsti(c)->clone_flags & CLONE_NEWPID) && c->ids && c->ids->pid_ns_id == task->ids->pid_ns_id)
			return c->ids->user_ns_id;
	}

	return root_ids->user_ns_id;
}

/*
 * Whether the parent of the task can set its pid in the pid namespace
 * it is forked into (the one of the parent): clone3() needs
 * CAP_CHECKPOINT_RESTORE in the user namespace owning that pid
 * namespace. A task has the capabilities of its own user namespace
 * and of the ones nested below it, not of the ancestor ones.
 */
static bool parent_can_set_pid(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	unsigned int owner;

	/* Zombies and helpers can have ids == 0 so we skip them */
	while (parent && !parent->ids)
		parent = parent->parent;

	/* The root task is forked by criu itself */
	if (!parent)
		return true;

	/* The user namespace of criu is an ancestor of all the others */
	if (parent->ids->user_ns_id == root_ids->user_ns_id)
		return true;

	owner = pidns_owner_userns(parent);
	if (owner == parent->ids->user_ns_id)
		return true;

	/* The parent is in the root task's user namespace and the pid namespace is owned by a nested one */
	if (!nested_ns_task_nested(parent) && owner != root_ids->user_ns_id)
		return true;

	return false;
}

/*
 * A task living in a nested user namespace has no capabilities in the
 * user namespace owning the inherited pid namespace, so it can not set
 * the pid of a child forked into it: the kernel fails clone3() with
 * set_tid. Such a child is restored with a random pid, and the tasks
 * waiting for the original one get an ECHILD error from wait*(), like
 * if it had died.
 */
bool nested_ns_pid_can_not_be_set(struct pstree_item *item)
{
	if (!nested_ns_enabled())
		return false;

	/* The pid is always set in the new pid namespace of the child. */
	if (rsti(item)->clone_flags & CLONE_NEWPID)
		return false;

	return !parent_can_set_pid(item);
}

/*
 * A task in a nested pid namespace is not visible by its vpid in the
 * /proc of the mount namespace copy, and a task forked by a one living
 * in a nested user namespace is restored with a random pid, as its
 * parent can not set it. Only the /proc/self one is usable then.
 */
bool nested_ns_pid_not_visible(struct pstree_item *item)
{
	if (!nested_ns_enabled())
		return false;

	return task_in_nested_pidns(item) || nested_ns_pid_can_not_be_set(item);
}

int nested_ns_set_tid(struct pstree_item *item, pid_t pid, pid_t *set_tid, int max)
{
	set_tid[0] = pid;

	if (!nested_ns_enabled())
		return 1;

	if (nested_ns_pid_can_not_be_set(item))
		return 0;

	if (rsti(item)->clone_flags & CLONE_NEWPID) {
		/*
		 * The task is the init one of the new pid namespace,
		 * with the pid it had in it: the one it sees itself
		 * at, which its own kin knows it by. For a task below
		 * the root one its pid in the namespace of the forking
		 * task is kept as well, e.g. for a docker-in-docker
		 * inner container which is tracked by its pid by the
		 * inner containerd-shim. The root task is forked from
		 * the criu one, so its pid can't be specified in it.
		 */
		set_tid[0] = item->own_ns_pid ? item->own_ns_pid : INIT_PID;
		if (item != root_item && max > 1 && parent_can_set_pid(item)) {
			set_tid[1] = pid;
			return 2;
		}
		if (item != root_item)
			pr_warn("The pid %d of the init task of a nested pid namespace can not be set in the parent one\n",
				pid);
		return 1;
	}

	/*
	 * The task is forked by a one living in a nested pid namespace:
	 * its pid in it differs from the one in the root one. It is
	 * restored with the one of its own namespace, which its own
	 * kin, e.g. the task which has forked it, knows it by. The one
	 * of the root namespace is not settable by its parent: setting
	 * a pid at an outer level needs a capability in the user
	 * namespace owning it, which a task of a nested one does not
	 * have.
	 */
	/*
	 * The pid of the own namespace can be requested only when the
	 * fork happens in it, i.e. the forking parent is a real member
	 * of the same pid namespace (it has the capabilities to set it
	 * there). The tasks which have entered the namespaces of an
	 * inner container may have ended up under a session helper of
	 * an ancestor one (a synthetic task carrying the ids of the
	 * container, but forked in the ancestor one): their pid at the
	 * level of the helper one is requested instead, as it is the
	 * one settable by it.
	 */
	if (item->own_ns_pid && item->own_ns_pid != pid &&
	    item->parent && item->parent->ids &&
	    item->parent->pid->state != TASK_HELPER &&
	    item->parent->ids->pid_ns_id == item->ids->pid_ns_id)
		set_tid[0] = item->own_ns_pid;

	return 1;
}

bool nested_ns_pid_ok(struct pstree_item *item, pid_t pid)
{
	pid_t expected;

	if (!nested_ns_enabled())
		return vpid(item) == pid;

	if (nested_ns_pid_can_not_be_set(item))
		return true;

	/*
	 * A task forked with CLONE_NEWPID is the init one of its new pid
	 * namespace, so getpid() returns INIT_PID in it, and not the vpid
	 * from the root pid namespace. A task living in a nested pid
	 * namespace is seen by its own kin at its own pid in it — unless
	 * it was forked under a session helper of an ancestor one (see
	 * nested_ns_set_tid): it sees itself at its pid of the helper
	 * one, the vpid.
	 */
	if (item->own_ns_pid && item->parent && item->parent->ids &&
	    item->parent->pid->state != TASK_HELPER &&
	    item->parent->ids->pid_ns_id == item->ids->pid_ns_id)
		expected = item->own_ns_pid;
	else
		expected = vpid(item);
	if (expected == pid)
		return true;

	return (rsti(item)->clone_flags & CLONE_NEWPID) && pid == INIT_PID;
}

pid_t nested_ns_expected_sid(struct pstree_item *item)
{
	if (!nested_ns_enabled())
		return item->sid;

	/*
	 * A task forked with CLONE_NEWPID is the init one of its new pid
	 * namespace, so setsid() returns its pid in it. The same for a
	 * task of a nested one: setsid() returns its own pid in it, which
	 * the members of its session know it by.
	 */
	if (rsti(item)->clone_flags & CLONE_NEWPID)
		return INIT_PID;

	return item->own_ns_pid ? item->own_ns_pid : item->sid;
}

bool nested_ns_inherited_sid_ok(struct pstree_item *item, pid_t sid)
{
	struct pstree_item *leader;

	if (!nested_ns_enabled() || !task_in_nested_pidns(item))
		return false;

	/*
	 * The session id is the pid of its leader: the own one of it in
	 * its pid namespace, which the members of the session are
	 * restored to see it at.
	 */
	leader = pstree_item_by_virt(item->sid);
	if (leader && leader->ids && leader->ids->pid_ns_id == item->ids->pid_ns_id) {
		if (sid == leader->own_ns_pid)
			return true;
		/*
		 * A task forked from the init of the pid namespace after
		 * the setsid() of it inherits its session, even when it
		 * was recorded in another one (e.g. a task re-parented
		 * under the init, see nested_ns_prepare_pstree()).
		 */
		if (sid == INIT_PID) {
			pr_warn("The session of %d is the one of the init of its pid namespace, not of %d\n", vpid(item),
				vpid(leader));
			return true;
		}
		return false;
	}

	/*
	 * The leader of the session lives outside of the pid namespace
	 * of the task (e.g. the shim which has exec-ed a task into an
	 * inner container): the session is not representable in it, the
	 * one inherited with the fork is kept.
	 */
	pr_warn("The session %d of %d is not visible in its pid namespace: keeping the inherited %d\n", item->sid,
		vpid(item), sid);
	return true;
}

bool nested_ns_pgid(struct pstree_item *item, pid_t *pgid)
{
	struct pstree_item *leader;

	*pgid = item->pgid;

	if (!nested_ns_enabled() || !task_in_nested_pidns(item))
		return true;

	/* The group leader: its own pid in its pid namespace. */
	if (item->pgid == vpid(item)) {
		*pgid = item->own_ns_pid ? item->own_ns_pid : vpid(item);
		return true;
	}

	leader = pstree_item_by_virt(item->pgid);
	if (leader && leader->ids && leader->own_ns_pid && leader->ids->pid_ns_id == item->ids->pid_ns_id) {
		*pgid = leader->own_ns_pid;
		return true;
	}

	/*
	 * The group leader lives outside of the pid namespace of the
	 * task: the group is not representable in it, the one inherited
	 * with the fork is kept.
	 */
	pr_debug("The group %d of %d is not visible in its pid namespace: keeping the inherited one\n", item->pgid,
		 vpid(item));
	return false;
}
