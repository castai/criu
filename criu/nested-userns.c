#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/futex.h>

#include "page.h"
#include "cr_options.h"
#include "imgset.h"
#include "pstree.h"
#include "rst_info.h"
#include "namespaces.h"
#include "cgroup.h"
#include "nested-ns.h"
#include "protobuf.h"
#include "proc_parse.h"
#include "servicefd.h"
#include "util.h"
#include "util-caps.h"

#include "common/lock.h"

#include "images/userns.pb-c.h"
#include "images/core.pb-c.h"

/*
 * The uid and gid maps of the nested user namespaces: dumped from the
 * view of the dumping criu, written by the parent task of the first
 * task of each namespace on restore, and the translations of the ids
 * between the views. See nested-ns.h.
 */

/*
 * Parse the id map of a user namespace, read from
 * /proc/<pid>/<name>. The extents array is filled with the
 * allocated entries, so it has to be freed by the caller.
 */
static int parse_map_file(pid_t pid, const char *name, UidGidExtent ***exts)
{
	char path[64];
	char buf[4096];
	int fd, len, nr = 0, off = 0;
	UidGidExtent *extents = NULL;

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len < 0) {
		pr_perror("Can't read %s", path);
		return -1;
	}
	buf[len] = '\0';

	while (off < len) {
		unsigned int first, lower_first, count;
		char *line = buf + off, *nl;

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		off = nl ? (nl - buf) + 1 : len;

		if (!line[0])
			continue;

		if (sscanf(line, "%u %u %u", &first, &lower_first, &count) != 3) {
			pr_err("Bad %s line '%s' of %d\n", name, line, pid);
			goto err;
		}

		extents = xrealloc(extents, (nr + 1) * sizeof(*extents));
		if (!extents)
			goto err;

		uid_gid_extent__init(&extents[nr]);
		extents[nr].first = first;
		extents[nr].lower_first = lower_first;
		extents[nr].count = count;
		nr++;
	}

	if (nr) {
		UidGidExtent **arr = xmalloc(nr * sizeof(*arr));
		int i;

		if (!arr)
			goto err;

		for (i = 0; i < nr; i++)
			arr[i] = &extents[i];

		*exts = arr;
		return nr;
	}

	xfree(extents);
	return 0;
err:
	xfree(extents);
	return -1;
}

static void free_map_exts(UidGidExtent **exts, int n)
{
	if (n > 0) {
		xfree(exts[0]);
		xfree(exts);
	}
}

/*
 * Dump the image of one nested user namespace. The mappings are
 * relative to its parent user namespace. The task which has created
 * the namespace is recorded, so the restore knows which one of the
 * tasks living in it has to create it again (see
 * nested_ns_fixup_clone_flags()): the first one met in the walk of
 * the tree, parents before children.
 */
static int dump_nested_userns(struct ns_id *ns)
{
	UsernsEntry e = USERNS_ENTRY__INIT;
	struct pstree_item *creator;
	struct cr_img *img;
	int ret = -1;

	ret = parse_map_file(ns->ns_pid, "uid_map", &e.uid_map);
	if (ret < 0)
		return -1;
	e.n_uid_map = ret;

	ret = parse_map_file(ns->ns_pid, "gid_map", &e.gid_map);
	if (ret < 0)
		goto out;
	e.n_gid_map = ret;

	/*
	 * The vpids of the tasks are not assigned yet at this point of
	 * the dump (dump_one_task() does it): read the pid of the task
	 * at the level of the root task's pid namespace directly.
	 */
	creator = pstree_item_by_real(ns->ns_pid);
	if (creator) {
		pid_t cpid = pid_at_dump_level(creator->pid->real, 0);

		if (cpid > 0) {
			e.has_creator_pid = true;
			e.creator_pid = cpid;
		}
	}

	ret = -1;
	img = open_image(CR_FD_USERNS, O_DUMP, ns->id);
	if (!img)
		goto out;

	ret = pb_write_one(img, &e, PB_USERNS);
	close_image(img);
out:
	free_map_exts(e.uid_map, e.n_uid_map);
	free_map_exts(e.gid_map, e.n_gid_map);
	return ret < 0 ? -1 : 0;
}

int nested_ns_collect_user_namespaces(void)
{
	struct ns_id *ns, *root_userns = NULL;
	bool nested = false;

	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &user_ns_desc)
			continue;

		if (ns->type == NS_ROOT)
			root_userns = ns;
		else if (ns->type == NS_OTHER)
			nested = true;
	}

	if (!root_userns && !nested)
		return 0;

	/*
	 * The root user namespace is dumped first, as its uid and
	 * gid mappings fill in the global userns_entry, which is
	 * used for converting local id-s to userns id-s
	 * (userns_uid(), userns_gid()).
	 */
	if (root_userns && dump_user_ns(root_userns->ns_pid, root_userns->id))
		return -1;

	/*
	 * Nested user namespaces are dumped with their own uid
	 * and gid mappings, which are relative to the user
	 * namespace they were created from.
	 */
	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &user_ns_desc || ns->type != NS_OTHER)
			continue;

		if (dump_nested_userns(ns))
			return -1;
	}

	return 0;
}

/*
 * Restore side
 */

int nested_ns_read_userns_img(unsigned int id, UsernsEntry **e)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_USERNS, O_RSTR, id);
	if (!img)
		return -1;
	ret = pb_read_one(img, e, PB_USERNS);
	close_image(img);

	return ret < 0 ? -1 : 0;
}

/*
 * Entering the user namespace of the restored tree and setting the
 * uid 0 of it makes criu leave the global root, which clears all
 * the capabilities, if the option is not set. Keep them, as the
 * tasks need them over the user namespace to restore the nested
 * ones, like a container runtime does when entering a user
 * namespace.
 */
int nested_ns_prepare_userns_creds(void)
{
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	struct __user_cap_header_struct hdr;
	int i;

	if (!opts.unprivileged || has_cap_setuid(opts.cap_eff)) {
		if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
			pr_perror("Unable to set PR_SET_KEEPCAPS");
			return -1;
		}

		/* UID and GID must be set after restoring /proc/PID/{uid,gid}_maps */
		if (setuid(0) || setgid(0) || setgroups(0, NULL)) {
			pr_perror("Unable to initialize id-s");
			return -1;
		}

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;
		if (capget(&hdr, data) < 0) {
			pr_perror("capget");
			return -1;
		}

		for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++)
			data[i].effective = data[i].permitted;

		if (capset(&hdr, data) < 0) {
			pr_perror("capset");
			return -1;
		}
	}

	/*
	 * This flag is dropped after entering the user namespace, but
	 * is required to access files in /proc, so put one here
	 * temporarily. It will be set to proper value at the very end.
	 */
	if (prctl(PR_SET_DUMPABLE, 1, 0)) {
		pr_perror("Unable to set PR_SET_DUMPABLE");
		return -1;
	}

	return 0;
}

bool nested_ns_needs_prep_creds(struct pstree_item *item)
{
	/*
	 * A task born in a new nested user namespace also has to
	 * prepare its credentials, after its parent writes the id
	 * maps of the namespace.
	 */
	return nested_ns_enabled() && item->parent && (rsti(item)->clone_flags & CLONE_NEWUSER);
}

/*
 * The handshake between the parent task and a child born in a new
 * user namespace goes over the userns_maps futex of the child:
 *   0  the child is not born yet
 *   1  the child has reported its pid, the parent may write the maps
 *   2  the maps are written, the child may apply its credentials
 * The waits are bounded: a task dying on either side aborts the
 * restore (see sigchld_handler()), which the waiter notices.
 */
static bool handshake_active(struct pstree_item *item)
{
	return nested_ns_enabled() && item->parent && (rsti(item)->clone_flags & CLONE_NEWUSER);
}

static int handshake_wait(struct pstree_item *item, uint32_t want)
{
	futex_t *f = &rsti(item)->userns_maps;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	for (;;) {
		uint32_t v = futex_get(f);

		if (v == want)
			return 0;
		if (v & FUTEX_ABORT_FLAG) {
			pr_err("The user namespace handshake of %d is aborted\n", vpid(item));
			return -1;
		}
		if (futex_get(&task_entries->nr_in_progress) & FUTEX_ABORT_FLAG) {
			pr_err("The restore is aborted while waiting for the user namespace handshake of %d\n",
			       vpid(item));
			return -1;
		}

		syscall(SYS_futex, &f->raw.counter, FUTEX_WAIT, v, &ts, NULL, 0);
	}
}

int nested_ns_child_init(struct pstree_item *item, unsigned long clone_flags)
{
	if (!nested_ns_enabled() || !(clone_flags & CLONE_NEWUSER) || !item->parent)
		return 0;

	/*
	 * The child will report its pid and then wait until we
	 * write the maps of the namespace.
	 */
	item->pid->real = 0;
	futex_set(&rsti(item)->userns_maps, 0);

	return 0;
}

/*
 * The lower ids of the dumped uid and gid maps are expressed in
 * the user namespace of the criu process which has dumped them.
 * But when the maps are written into the files of a nested user
 * namespace, the kernel interprets them in its parent user
 * namespace, so they have to be translated via the mappings of
 * the latter, which are dumped in the same criu view.
 */
static int translate_lower_ids(UidGidExtent **extents, int n, UidGidExtent **parent, int pn)
{
	int i, j;

	for (i = 0; i < n; i++) {
		for (j = 0; j < pn; j++) {
			UidGidExtent *e = extents[i], *p = parent[j];

			if (p->lower_first <= e->lower_first && e->lower_first + e->count <= p->lower_first + p->count) {
				e->lower_first = p->first + (e->lower_first - p->lower_first);
				break;
			}
		}

		if (j == pn) {
			pr_err("No mapping for the id %u in the parent user namespace\n", extents[i]->lower_first);
			return -1;
		}
	}

	return 0;
}

/*
 * Write the uid/gid maps of a nested user namespace via the /proc
 * of the criu process. The local /proc of the restored tasks may
 * be mounted in another pid namespace, in which the child has
 * another pid.
 */
static int write_id_map_crfd(pid_t pid, UidGidExtent **extents, int n, char *id_map)
{
	char buf[PAGE_SIZE];
	char path[64];
	int off = 0, i, dfd, fd;

	/*
	 * A user namespace may have no id mappings at all: it was
	 * created with an empty map, and it is left as is. The kernel
	 * rejects an empty write into a uid_map or a gid_map file, so
	 * there is nothing to write for such a namespace, as a freshly
	 * created one already has an empty map.
	 */
	if (n == 0)
		return 0;

	/*
	 * We can perform only a single write (that may contain multiple
	 * newline-delimited records) to a uid_map and a gid_map file.
	 */
	for (i = 0; i < n; i++) {
		int len;

		len = snprintf(buf + off, sizeof(buf) - off, "%u %u %u\n", extents[i]->first, extents[i]->lower_first,
			       extents[i]->count);
		if (len < 0 || len >= sizeof(buf) - off) {
			pr_err("Unable to form the user/group mappings buffer\n");
			return -1;
		}
		off += len;
	}

	dfd = get_service_fd(CR_PROC_FD_OFF);
	if (dfd < 0) {
		pr_err("Can't get criu proc fd\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%d/%s", pid, id_map);
	fd = openat(dfd, path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	pr_debug("NestedNS: writing '%.*s' to %s (buf off %d, n %d)\n", off, buf, path, off, n);

	if (write(fd, buf, off) != off) {
		pr_perror("Unable to write into %s", id_map);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/*
 * Whether the id, in the view of the user namespace described by the
 * given extents, is mapped in it, i.e. can be set from inside of it.
 */
static bool id_mapped_in_ns(u32 id, UidGidExtent **extents, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (extents[i]->first <= id && id - extents[i]->first < extents[i]->count)
			return true;
	}

	return false;
}

static int fix_creds_entry(CredsEntry *ce, UsernsEntry *e, struct pstree_item *item)
{
	int n_groups = 0, i;

	if (!id_mapped_in_ns(ce->uid, e->uid_map, e->n_uid_map) || !id_mapped_in_ns(ce->euid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->suid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->fsuid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->gid, e->gid_map, e->n_gid_map) || !id_mapped_in_ns(ce->egid, e->gid_map, e->n_gid_map) ||
	    !id_mapped_in_ns(ce->sgid, e->gid_map, e->n_gid_map) ||
	    !id_mapped_in_ns(ce->fsgid, e->gid_map, e->n_gid_map)) {
		pr_err("The ids of the task %d are not mapped in its user namespace\n", vpid(item));
		return -1;
	}

	for (i = 0; i < ce->n_groups; i++) {
		if (id_mapped_in_ns(ce->groups[i], e->gid_map, e->n_gid_map)) {
			ce->groups[n_groups++] = ce->groups[i];
			continue;
		}

		pr_warn("The group %u of the task %d is not mapped in its user namespace: it is dropped\n", ce->groups[i],
			vpid(item));
	}
	ce->n_groups = n_groups;

	return 0;
}

/*
 * The ids of the credentials of a task living in a nested user
 * namespace are dumped in the view of that namespace (they are read
 * by the parasite from inside of the task), which is the one they
 * are restored (set with setresuid() & co by the restorer) in. The
 * group ids which are not mapped in the namespace can not be set
 * with setgroups(): they are the ones inherited from a parent
 * namespace at fork, which are not visible in this one anyway, so
 * they are dropped. Called for the core of every thread.
 */
int nested_ns_fix_task_creds(struct pstree_item *item, CoreEntry *core)
{
	static UsernsEntry *cached;
	static unsigned int cached_id;
	int ret;

	if (!nested_ns_task_nested(item) || !item->parent)
		return 0;

	if (!core->thread_core || !core->thread_core->creds)
		return 0;

	if (!cached || cached_id != item->ids->user_ns_id) {
		if (cached)
			userns_entry__free_unpacked(cached, NULL);
		cached = NULL;
		if (nested_ns_read_userns_img(item->ids->user_ns_id, &cached))
			return -1;
		cached_id = item->ids->user_ns_id;
	}

	ret = fix_creds_entry(core->thread_core->creds, cached, item);

	return ret;
}

/*
 * We are the parent task of the one just born in a new user
 * namespace, so we are the one to fill in its uid and gid maps.
 */
static int write_child_userns_maps(struct pstree_item *item, pid_t real_pid)
{
	UsernsEntry *e = NULL, *pe = NULL;
	struct pstree_item *parent = item->parent;
	int ret = -1;

	if (nested_ns_read_userns_img(item->ids->user_ns_id, &e))
		return -1;

	/* Zombies and helpers can have ids == 0 so we skip them */
	while (parent && !parent->ids)
		parent = parent->parent;

	/*
	 * If our user namespace is not the one of the criu process
	 * which has dumped the tree (root_ids, from the inventory),
	 * translate the lower ids into its view, as this is the one in
	 * which the kernel writes the maps of the new namespace.
	 */
	if (parent && parent->ids->user_ns_id != root_ids->user_ns_id) {
		if (nested_ns_read_userns_img(parent->ids->user_ns_id, &pe))
			goto out;

		if (translate_lower_ids(e->uid_map, e->n_uid_map, pe->uid_map, pe->n_uid_map))
			goto out;

		if (translate_lower_ids(e->gid_map, e->n_gid_map, pe->gid_map, pe->n_gid_map))
			goto out;
	}

	if (write_id_map_crfd(real_pid, e->uid_map, e->n_uid_map, "uid_map"))
		goto out;

	if (write_id_map_crfd(real_pid, e->gid_map, e->n_gid_map, "gid_map"))
		goto out;

	ret = 0;
out:
	if (pe)
		userns_entry__free_unpacked(pe, NULL);
	userns_entry__free_unpacked(e, NULL);
	return ret;
}

int nested_ns_child_forked(struct pstree_item *item, unsigned long clone_flags, pid_t real)
{
	if (!nested_ns_enabled() || !(clone_flags & CLONE_NEWUSER) || !item->parent)
		return 0;

	/*
	 * The child reports its pid in our pid namespace and waits
	 * for us to fill in the maps of its user namespace before
	 * setting its credentials.
	 */
	if (handshake_wait(item, 1))
		goto err;

	if (item->pid->real <= 0) {
		pr_err("Can't get the pid of the task %d\n", vpid(item));
		goto err;
	}

	if (write_child_userns_maps(item, item->pid->real))
		goto err;

	/*
	 * The child has no permissions over the cgroups, owned by our
	 * user namespace: move it into its ones from here, before it
	 * creates its cgroup namespace (see nested_ns_child_namespaces()).
	 */
	if (restore_child_cgroup(item, real))
		goto err;

	/* The child may apply its credentials now. */
	futex_set_and_wake(&rsti(item)->userns_maps, 2);

	return 0;

err:
	/*
	 * real is the pid of the child in our pid namespace, as clone()
	 * has returned it: the vpid of the task may differ from it (a
	 * random one, or the one of an inner pid namespace).
	 */
	futex_abort_and_wake(&rsti(item)->userns_maps);
	kill(real, SIGKILL);
	waitpid(real, NULL, 0);
	return -1;
}

int nested_ns_child_report(struct pstree_item *item)
{
	if (!handshake_active(item))
		return 0;

	/*
	 * Report our pid to the parent task, which is going to
	 * write the maps of our user namespace for us.
	 */
	futex_set_and_wake(&rsti(item)->userns_maps, 1);

	return 0;
}

int nested_ns_child_wait(struct pstree_item *item)
{
	if (!handshake_active(item))
		return 0;

	/*
	 * Our parent has to write the uid and gid maps of our user
	 * namespace before we can set our credentials.
	 */
	return handshake_wait(item, 2);
}

void nested_ns_child_abort(struct pstree_item *item)
{
	if (!handshake_active(item))
		return;

	futex_abort_and_wake(&rsti(item)->userns_maps);
}

/*
 * Join the user namespace created by the first task of the tree living
 * in it, so that the namespaces owned by it are enterable. Called for the
 * tasks which were forked without CLONE_NEWUSER (see
 * nested_ns_fixup_clone_flags()): they run in the user namespace of the
 * restoring criu, from which the one of the container is enterable.
 */
int nested_ns_join_userns(struct pstree_item *item)
{
	struct pstree_item *creator;
	char path[64];
	int dfd, fd;

	/*
	 * Find the creator: the task which has kept the CLONE_NEWUSER flag,
	 * i.e. the one which has created the namespace at its fork.
	 */
	for_each_pstree_item(creator) {
		if (creator->ids && creator->ids->user_ns_id == item->ids->user_ns_id &&
		    (rsti(creator)->clone_flags & CLONE_NEWUSER) && creator->pid->real > 0)
			break;
	}
	if (!creator || !creator->ids || creator->ids->user_ns_id != item->ids->user_ns_id) {
		pr_err("Can't find the creator of the user namespace of %d\n", vpid(item));
		return -1;
	}

	dfd = get_service_fd(CR_PROC_FD_OFF);
	if (dfd < 0) {
		pr_err("Can't get criu proc fd\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%d/ns/user", creator->pid->real);
	fd = openat(dfd, path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (setns(fd, CLONE_NEWUSER)) {
		pr_perror("Can't join the user namespace of %d", creator->pid->real);
		close(fd);
		return -1;
	}
	close(fd);

	/*
	 * Set the ids to the root of the namespace, with the full set of
	 * capabilities in it, the same way as the creator of the namespace
	 * does after the maps of it are written.
	 */
	if (prctl(PR_SET_KEEPCAPS, 1)) {
		pr_perror("Unable to set PR_SET_KEEPCAPS");
		return -1;
	}
	if (setresgid(0, 0, 0) || setgroups(0, NULL)) {
		pr_perror("Unable to set group ID");
		return -1;
	}
	if (setresuid(0, 0, 0)) {
		pr_perror("Unable to set user ID");
		return -1;
	}
	if (prctl(PR_SET_DUMPABLE, 1, 0)) {
		pr_perror("Unable to set PR_SET_DUMPABLE");
		return -1;
	}

	pr_debug("Joined the user namespace of the task %d\n", vpid(creator));

	return 0;
}

/*
 * The ids in the images are the ones of the view of the root task's
 * user namespace (see userns_uid()). A task restored into a nested one
 * sees the ids translated by its id maps: a chown with such an id is
 * rejected there (EINVAL, unmapped). Translate the ids to the view of
 * the namespace the current task is in. The maps are read from our own
 * /proc entry, which shows their lower ids in the view of the parent
 * user namespace: the root one, as only one level of nesting is
 * supported. They are cached per process: the namespace of a task does
 * not change once its credentials are applied.
 */
#define IDMAP_MAX_EXTENTS 340

struct idmap_cache {
	pid_t pid;
	int n;
	struct {
		unsigned int first, lower, count;
	} ext[IDMAP_MAX_EXTENTS];
};

static struct idmap_cache uid_cache, gid_cache;

static struct idmap_cache *idmap_get(bool is_uid)
{
	struct idmap_cache *c = is_uid ? &uid_cache : &gid_cache;
	pid_t pid = getpid();
	FILE *map;

	if (c->pid == pid)
		return c;

	c->pid = pid;
	c->n = 0;

	map = fopen(is_uid ? "/proc/self/uid_map" : "/proc/self/gid_map", "r");
	if (!map)
		return c;

	while (c->n < IDMAP_MAX_EXTENTS &&
	       fscanf(map, "%u %u %u", &c->ext[c->n].first, &c->ext[c->n].lower, &c->ext[c->n].count) == 3)
		c->n++;

	fclose(map);
	return c;
}

void nested_ns_view_id(unsigned int *id, bool is_uid)
{
	struct idmap_cache *c;
	int i;

	if (!nested_ns_task_nested(current))
		return;

	c = idmap_get(is_uid);
	for (i = 0; i < c->n; i++) {
		if (*id >= c->ext[i].lower && *id - c->ext[i].lower < c->ext[i].count) {
			*id = *id - c->ext[i].lower + c->ext[i].first;
			return;
		}
	}
}
