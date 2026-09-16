#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <linux/capability.h>
#include <linux/nsfs.h>

#ifndef NS_GET_PARENT
#define NS_GET_PARENT _IO(NSIO, 0x2)
#endif

#include "page.h"
#include "cr_options.h"
#include "imgset.h"
#include "pstree.h"
#include "namespaces.h"
#include "nested-ns.h"
#include "uts_ns.h"
#include "net.h"
#include "ipc_ns.h"
#include "cgroup.h"
#include "mount.h"
#include "filesystems.h"
#include "images/mnt.pb-c.h"
#include "protobuf.h"
#include "servicefd.h"
#include "util.h"
#include "util-caps.h"
#include "fdstore.h"

#include "common/lock.h"

#include "images/userns.pb-c.h"
#include "images/core.pb-c.h"

/*
 * Everything below this check is only active with the --nested-ns
 * option, otherwise criu behaves exactly like without it.
 */
bool nested_ns_enabled(void)
{
	return opts.nested_ns;
}

/*
 * Dump side
 */

bool nested_ns_dump_ok(struct ns_desc *nd)
{
	/*
	 * User, uts, net, pid, ipc and cgroup namespaces may be
	 * nested for now (e.g. for a docker-in-docker container).
	 * A nested cgroup namespace is taken into the image, but it
	 * is not re-created on restore: its processes run in the one
	 * of their parent task. All the other ones keep failing with
	 * the usual error.
	 */
	return nested_ns_enabled() &&
	       (nd == &user_ns_desc || nd == &uts_ns_desc || nd == &net_ns_desc ||
		nd == &pid_ns_desc || nd == &ipc_ns_desc || nd == &cgroup_ns_desc);
}

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
 * relative to its parent user namespace.
 */
static int dump_nested_userns(struct ns_id *ns)
{
	UsernsEntry e = USERNS_ENTRY__INIT;
	struct cr_img *img;
	int ret;

	ret = parse_map_file(ns->ns_pid, "uid_map", &e.uid_map);
	if (ret < 0)
		return -1;
	e.n_uid_map = ret;

	ret = parse_map_file(ns->ns_pid, "gid_map", &e.gid_map);
	if (ret < 0)
		return -1;
	e.n_gid_map = ret;

	img = open_image(CR_FD_USERNS, O_DUMP, ns->id);
	if (!img)
		return -1;
	ret = pb_write_one(img, &e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		return -1;

	free_map_exts(e.uid_map, e.n_uid_map);
	free_map_exts(e.gid_map, e.n_gid_map);

	return 0;
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
 * On restore a user namespace is recreated when the parent task
 * forks a task living in it, so its uid and gid mappings have to be
 * relative to the user namespace of the parent task. Check that
 * they really are a child of it, and not of any other user
 * namespace.
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
		return 0;
	}

	/*
	 * The task which enters the nested user namespace may have
	 * its own pid, network and mount namespaces, which are created
	 * by it on restore. A nested cgroup namespace is taken into
	 * the image, but is not re-created on restore: the processes
	 * run in the one of their parent task. The time namespace is
	 * not supported yet.
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
		pr_err("The user namespace of %d is not a child of the user namespace of its parent task\n", item->pid->real);
		return -1;
	}

	return 0;
}

int nested_ns_check_task(struct pstree_item *item)
{
	if (!nested_ns_enabled())
		return 0;

	if (!item->parent)
		return 0;

	return check_nested_user_ns(item);
}

/*
 * Restore side
 */

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
	return item->parent && (rsti(item)->clone_flags & CLONE_NEWUSER);
}

int nested_ns_child_init(struct pstree_item *item, unsigned long clone_flags)
{
	if (!(clone_flags & CLONE_NEWUSER) || !item->parent)
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

/*
 * The ids of the credentials of a task living in a nested user
 * namespace are dumped in the view of that namespace (they are read
 * by the parasite from inside of the task), which is the one they
 * are restored (set with setresuid() & co by the restorer) in. The
 * group ids which are not mapped in the namespace can not be set
 * with setgroups(): they are the ones inherited from a parent
 * namespace at fork, which are not visible in this one anyway, so
 * they are dropped.
 */
int nested_ns_fix_task_creds(struct pstree_item *item, CoreEntry *core)
{
	UsernsEntry *e;
	CredsEntry *ce;
	struct cr_img *img;
	int n_groups = 0, i, ret;

	if (!nested_ns_enabled())
		return 0;

	/* Zombies and helpers can have ids == 0 so we skip them */
	if (!item->ids || !item->parent || !root_item->ids)
		return 0;

	if (item->ids->user_ns_id == root_item->ids->user_ns_id)
		return 0;

	img = open_image(CR_FD_USERNS, O_RSTR, item->ids->user_ns_id);
	if (!img)
		return -1;
	ret = pb_read_one(img, &e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		return -1;

	ce = core->thread_core->creds;

	if (!id_mapped_in_ns(ce->uid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->euid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->suid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->fsuid, e->uid_map, e->n_uid_map) ||
	    !id_mapped_in_ns(ce->gid, e->gid_map, e->n_gid_map) ||
	    !id_mapped_in_ns(ce->egid, e->gid_map, e->n_gid_map) ||
	    !id_mapped_in_ns(ce->sgid, e->gid_map, e->n_gid_map) ||
	    !id_mapped_in_ns(ce->fsgid, e->gid_map, e->n_gid_map)) {
		pr_err("The ids of the task %d are not mapped in its user namespace\n", vpid(item));
		goto err;
	}

	for (i = 0; i < ce->n_groups; i++) {
		if (id_mapped_in_ns(ce->groups[i], e->gid_map, e->n_gid_map)) {
			ce->groups[n_groups++] = ce->groups[i];
			continue;
		}

		pr_warn("The group %u of the task %d is not mapped in its user namespace: it is dropped\n",
			 ce->groups[i], vpid(item));
	}
	ce->n_groups = n_groups;

	userns_entry__free_unpacked(e, NULL);
	return 0;
err:
	userns_entry__free_unpacked(e, NULL);
	return -1;
}

/*
 * We are the parent task of the one just born in a new user
 * namespace, so we are the one to fill in its uid and gid maps.
 */
static int write_child_userns_maps(struct pstree_item *item, pid_t real_pid)
{
	struct cr_img *img;
	UsernsEntry *e;
	int ret;

	img = open_image(CR_FD_USERNS, O_RSTR, item->ids->user_ns_id);
	if (!img)
		return -1;
	ret = pb_read_one(img, &e, PB_USERNS);
	close_image(img);
	if (ret < 0)
		return -1;

	/*
	 * If our user namespace is not the one of the criu process
	 * which has dumped the tree, translate the lower ids into
	 * its view, as this is the one in which the kernel writes
	 * the maps of the new namespace.
	 */
	{
		struct pstree_item *parent = item->parent;

		/* Zombies and helpers can have ids == 0 so we skip them */
		while (parent && !parent->ids)
			parent = parent->parent;

		if (parent && parent->ids->user_ns_id != root_ids->user_ns_id) {
			struct cr_img *pimg;
			UsernsEntry *pe;
			int pret;

			pimg = open_image(CR_FD_USERNS, O_RSTR, parent->ids->user_ns_id);
			if (!pimg)
				return -1;
			pret = pb_read_one(pimg, &pe, PB_USERNS);
			close_image(pimg);
			if (pret < 0)
				return -1;

			if (translate_lower_ids(e->uid_map, e->n_uid_map, pe->uid_map, pe->n_uid_map))
				return -1;

			if (translate_lower_ids(e->gid_map, e->n_gid_map, pe->gid_map, pe->n_gid_map))
				return -1;
		}
	}

	if (write_id_map_crfd(real_pid, e->uid_map, e->n_uid_map, "uid_map"))
		return -1;

	if (write_id_map_crfd(real_pid, e->gid_map, e->n_gid_map, "gid_map"))
		return -1;

	return 0;
}

static int nested_ns_chmod_images(void)
{
	/*
	 * The checkpoint image files are owned by root, and the task
	 * entering a nested user namespace runs as the remapped user
	 * on the node, so it can't read them. Make them readable.
	 */
	char cmd[PATH_MAX];
	char *dir = opts.imgs_dir;

	if (!dir)
		return 0;

	snprintf(cmd, sizeof(cmd), "chmod -R a+r '%s'", dir);
	if (system(cmd)) {
		pr_warn("Can't make the image directory readable\n");
	}
	return 0;
}

/*
 * Pin the root fds of the nested mount namespaces into the fdstore
 * before any task of the tree is forked: the file ones (e.g. the unix
 * socket ones) of a task restoring early may be resolved in one of them,
 * and the first task of the namespace forks too late to have it pinned
 * in time.
 *
 * It is called from the root task, with the mount namespaces assembled
 * and their root fds set: the root filesystem of a nested one is either
 * a path in the one of its parent (e.g. the /docker-data/vfs/dir/<id> of
 * the vfs driver of an inner docker), or the same overlay mounted at a
 * different path in it, so it is opened by that path.
 */
int nested_ns_pin_roots(void)
{
	struct ns_id *root_ns, *nsid;
	int root_fd;

	if (!nested_ns_enabled())
		return 0;

	root_ns = lookup_ns_by_id(root_item->ids->mnt_ns_id, &mnt_ns_desc);
	if (!root_ns) {
		pr_err("Can't find the root mount namespace\n");
		return -1;
	}

	root_fd = mntns_get_root_fd(root_ns);
	if (root_fd < 0) {
		pr_err("Can't get the root fd of the root mount namespace\n");
		return -1;
	}

	for (nsid = ns_ids; nsid; nsid = nsid->next) {
		struct mount_info *mi, *root_mi = NULL;
		char rootfs_path[PATH_MAX];
		int found = 0, fd, id;

		if (nsid->nd != &mnt_ns_desc || !nested_ns_own_mntns(nsid))
			continue;

		if (nsid->mnt.root_fd_id >= 0)
			continue;

		for (mi = nsid->mnt.mntinfo_tree; mi; mi = mi->next) {
			if (!strcmp(mi->ns_mountpoint, "/")) {
				root_mi = mi;
				break;
			}
		}
		if (!root_mi) {
			pr_err("Can't find the root mount of the nested mntns %d\n", nsid->id);
			return -1;
		}

		if (root_mi->root && root_mi->root[0] == '/' && strcmp(root_mi->root, "/")) {
			/* A bind mount of a directory of the parent's filesystem */
			snprintf(rootfs_path, sizeof(rootfs_path), "%s", root_mi->root);
			found = 1;
		} else {
			/* The overlayfs of the inner container: find the same one in the parent's tree */
			for (mi = root_ns->mnt.mntinfo_tree; mi; mi = mi->next) {
				if (mi->s_dev == root_mi->s_dev &&
				    mi->fstype->code == FSTYPE__OVERLAYFS) {
					snprintf(rootfs_path, sizeof(rootfs_path), "%s", mi->ns_mountpoint);
					found = 1;
					break;
				}
			}
		}

		if (!found) {
			pr_warn("Can't find the rootfs of the nested mntns %d: its root fd is not pinned early\n",
				 nsid->id);
			continue;
		}

		fd = openat(root_fd, rootfs_path + 1, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("Can't open the rootfs %s of the nested mntns %d", rootfs_path, nsid->id);
			continue;
		}

		id = fdstore_add(fd);
		close(fd);
		if (id < 0) {
			pr_err("Can't add the root fd of the nested mntns %d\n", nsid->id);
			continue;
		}

		nsid->mnt.root_fd_id = id;
		pr_debug("Pinned the root fd of the nested mntns %d (fdstore id %d)\n", nsid->id, id);
	}

	return 0;
}

/*
 * A task of the tree which has entered a nested user namespace without
 * creating it (e.g. a docker exec-ed process of an inner container) gets
 * the CLONE_NEWUSER flag derived from the difference of its namespace
 * ids from the ones of its parent, so at restore it would fork into its
 * own copy of the user namespace, a sibling of the original one, and
 * would not be able to enter the namespaces owned by it. Only the first
 * task of a user namespace (the one which has created it at dump) keeps
 * the flag: the others are forked without it and join the created one.
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
 */
void nested_ns_fix_exec_pstree(void)
{
	struct pstree_item *item;

	if (!nested_ns_enabled())
		return;

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
		if (item->ids->pid_ns_id == parent->ids->pid_ns_id &&
		    item->ids->mnt_ns_id == parent->ids->mnt_ns_id &&
		    item->ids->user_ns_id == parent->ids->user_ns_id)
			continue;

		/*
		 * Find the home for the task: the first one in its
		 * mount namespace which is not a descendant of it (the
		 * init one of the inner container, normally).
		 */
		home = NULL;
		for_each_pstree_item(home) {
			if (home == item || !home->ids || !home->parent)
				continue;

			if (home->ids->mnt_ns_id == item->ids->mnt_ns_id &&
			    home->ids->pid_ns_id == item->ids->pid_ns_id &&
			    home->ids->user_ns_id == item->ids->user_ns_id &&
			    home->pid->state != TASK_DEAD) {
				/* not a descendant of item */
				struct pstree_item *p = home;

				while (p && p != item)
					p = p->parent;
				if (!p)
					break;
			}
		}
		if (!home || !home->ids || home == item)
			continue;

		pr_info("Re-parenting the task %d from %d to %d: it has entered the namespaces of the one at dump\n",
			vpid(item), vpid(parent), vpid(home));

		list_del(&item->sibling);
		item->parent = home;
		list_add_tail(&item->sibling, &home->children);
	}
}

void nested_ns_fix_exec_userns(void)
{
	struct pstree_item *item, *creator;

	if (!nested_ns_enabled())
		return;

	/*
	 * For each nested user namespace, the task which has created it at
	 * dump is the one with the lowest pid in it: the ones which have
	 * entered it later (e.g. the docker exec-ed processes of an inner
	 * container) have higher ones. Only the creator keeps the
	 * CLONE_NEWUSER flag, so the namespace is created once: the others
	 * are forked without it and join the created one.
	 */
	for_each_pstree_item(item) {
		if (!item->parent || !item->ids || !root_item->ids)
			continue;

		if (!(rsti(item)->clone_flags & CLONE_NEWUSER))
			continue;

		if (item->ids->user_ns_id == root_item->ids->user_ns_id)
			continue;

		creator = NULL;
		for_each_pstree_item(creator) {
			if (!creator->parent || !creator->ids)
				continue;

			if (!(rsti(creator)->clone_flags & CLONE_NEWUSER))
				continue;

			if (creator->ids->user_ns_id == item->ids->user_ns_id &&
			    vpid(creator) < vpid(item))
				break;
		}
		if (creator && creator->ids && creator->ids->user_ns_id == item->ids->user_ns_id &&
		    vpid(creator) < vpid(item)) {
			rsti(item)->clone_flags &= ~CLONE_NEWUSER;
		}
	}
}

/*
 * Join the user namespace created by the first task of the tree living
 * in it, so that the namespaces owned by it are enterable. Called for the
 * tasks which were forked without CLONE_NEWUSER (see above): they run in
 * the user namespace of the restoring criu, from which the one of the
 * container is enterable.
 */
static int nested_ns_join_userns(struct pstree_item *item)
{
	struct pstree_item *creator;
	char path[64];
	int dfd, fd;

	creator = item;
	while (creator->parent) {
		struct pstree_item *parent = creator->parent;

		/* Zombies and helpers can have ids == 0 so we skip them */
		while (parent && !parent->ids)
			parent = parent->parent;
		if (!parent)
			break;

		if (parent->ids->user_ns_id == item->ids->user_ns_id)
			break;

		/*
		 * The nearest ancestor with the same user namespace... no:
		 * find the FIRST task of the namespace, which has created it.
		 */
		break;
	}

	/* Find the creator: the task which has kept the CLONE_NEWUSER flag,
	 * i.e. the one which has created the namespace at its fork. */
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

int nested_ns_child_forked(struct pstree_item *item, unsigned long clone_flags, pid_t pid)
{
	if (!(clone_flags & CLONE_NEWUSER) || !item->parent)
		return 0;

	nested_ns_chmod_images();

	/*
	 * The child has reported its pid in our pid namespace and
	 * is waiting for us to fill in the maps of its user
	 * namespace before setting its credentials.
	 */
	futex_wait_until(&rsti(item)->userns_maps, 1);

	if (futex_get(&rsti(item)->userns_maps) != 1 || item->pid->real <= 0) {
		pr_err("Can't get the pid of the task %d\n", vpid(item));
		return -1;
	}

	if (write_child_userns_maps(item, item->pid->real)) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}

	/* The child may apply its credentials now. */
	futex_set_and_wake(&rsti(item)->userns_maps, 2);

	return 0;
}

int nested_ns_child_report(struct pstree_item *item)
{
	if (!item->parent || !(rsti(item)->clone_flags & CLONE_NEWUSER))
		return 0;

	/*
	 * Report our pid to the parent task, which is going to
	 * write the maps of our user namespace for us.
	 */
	futex_set_and_wake(&rsti(item)->userns_maps, 1);

	return 0;
}

/*
 * The start time of a process, as it is recorded in its /proc stat:
 * the identifier of the boot of the running kernel, which the runtimes
 * (e.g. runc) use to tell a process from a re-used pid.
 */
static unsigned long nested_proc_starttime(const char *proc_root, pid_t pid)
{
	char buf[4096], *p;
	int fd, n, field;

	snprintf(buf, sizeof(buf), "%s/%d/stat", proc_root, pid);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	/* The fields after the (comm) one, the starttime is the 22nd. */
	p = strrchr(buf, ')');
	if (!p)
		return 0;

	for (field = 2, p++; field < 22 && *p; p++)
		if (*p == ' ')
			field++;
	if (field != 22)
		return 0;

	return strtoul(p, NULL, 10);
}

static int nested_patch_state_json(const char *proc_root, const char *path)
{
	char buf[32768], *start_f, *pid_f, *end;
	unsigned long st;
	pid_t pid;
	int fd, n, len;
	char *out;

	fd = open(path, O_RDWR);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		close(fd);
		return 0;
	}
	buf[n] = '\0';

	pid_f = strstr(buf, "\"init_process_pid\":");
	if (!pid_f) {
		close(fd);
		return 0;
	}
	pid = strtoul(pid_f + sizeof("\"init_process_pid\":") - 1, NULL, 10);

	start_f = strstr(buf, "\"init_process_start\":");
	if (!start_f) {
		close(fd);
		return 0;
	}

	st = nested_proc_starttime(proc_root, pid);
	if (!st) {
		/* The init process is not visible: leave the state as it is. */
		return 0;
	}

	end = start_f + sizeof("\"init_process_start\":") - 1;
	while (*end >= '0' && *end <= '9')
		end++;

	out = xmalloc(n + 32);
	if (!out) {
		close(fd);
		return -1;
	}
	len = snprintf(out, (start_f - buf) + 48, "%.*s\"init_process_start\":%lu", (int)(start_f - buf), buf, st);
	memcpy(out + len, end, buf + n - end);
	len += buf + n - end;

	if (lseek(fd, 0, SEEK_SET) < 0 || write(fd, out, len) != len)
		pr_warn("Can't update the start time of the init process in %s\n", path);

	xfree(out);
	close(fd);
	return 0;
}

static const char *nested_proc_root = "/proc";

static int nested_state_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	size_t len = strlen(fpath);

	if (typeflag != FTW_F || len < 11 || strcmp(fpath + len - 11, "/state.json"))
		return 0;

	return nested_patch_state_json(nested_proc_root, fpath);
}

/*
 * The inner runtimes (e.g. the runc one of a docker-in-docker) keep the
 * state of the containers they run in their own files, which are
 * restored as they were at the dump time. The one of a container
 * records the pid and the start time of its init process: the pid is
 * restored, but the start time is the one of the freshly forked
 * process, and the identity check of the runtime fails on it, e.g. an
 * exec into the container is refused with "cannot exec in a stopped
 * container". Walk the runtime state files of the restored tree and
 * update the start time of the init processes in them.
 */
void nested_ns_patch_runc_states(void)
{
	char proc_root[] = "/tmp/.criu-proc-XXXXXX";
	bool mounted = false;

	if (!nested_ns_enabled())
		return;

	/*
	 * The /proc of the root task of the restore is the one of the
	 launching criu one, which sees the processes in the pid
	 * namespace of the node: the init processes of the inner
	 * containers are not reachable by their pids in it. Mount a
	 * fresh procfs, which is bound to our own pid namespace, the
	 * one of the restored tree root, so they are.
	 */
	if (mkdtemp(proc_root)) {
		if (mount("proc", proc_root, "proc", 0, NULL) == 0) {
			mounted = true;
			nested_proc_root = proc_root;
		} else {
			pr_warn("Can't mount a fresh procfs at %s: %s\n", proc_root, strerror(errno));
			rmdir(proc_root);
		}
	}

	if (nftw("/run", nested_state_cb, 12, FTW_PHYS) < 0)
		pr_warn("Can't walk the runtime state files of /run\n");

	if (mounted) {
		umount(proc_root);
		rmdir(proc_root);
	}
}

int nested_ns_child_wait(struct pstree_item *item)
{
	if (!item->parent || !(rsti(item)->clone_flags & CLONE_NEWUSER))
		return 0;

	/*
	 * Our parent has to write the uid and gid maps of our user
	 * namespace before we can set our credentials.
	 */
	futex_wait_until(&rsti(item)->userns_maps, 2);

	return 0;
}

/*
 * The numeric ids of a tar (ustar) archive entry are stored in the
 * octal notation: parse one.
 */
static unsigned int tar_octal(const char *p, int len)
{
	unsigned int v = 0;
	int i;

	for (i = 0; i < len && p[i] >= '0' && p[i] <= '7'; i++)
		v = v * 8 + (p[i] - '0');

	return v;
}

/*
 * The archive of the tmpfs content is created in the context of the
 * dumping criu, so the ids of its entries are the ones of the kernel
 * view of the dump time user namespaces. The task restoring the content
 * of a tmpfs of a nested user namespace runs in it: the tar of an inner
 * container (a busybox one, normally) can not set such ids, as they are
 * not mapped in it, and the extracted files end up owned by itself.
 * Walk the archive here and fix the ownership of the extracted files
 * with the ids translated to the view of the current user namespace.
 */
static int nested_fix_tmpfs_ownership(struct cr_img *img, const char *root)
{
	char hdr[512], full[512], lname[256];
	const char *file;
	int ifd = img_raw_fd(img), dfd;
	unsigned int uid, gid, size;
	char typeflag;
	int ret = 0;

	dfd = open(root, O_RDONLY | O_DIRECTORY);
	if (dfd < 0) {
		pr_perror("Can't open the tmpfs root %s", root);
		return -1;
	}

	/* The tar has read the image to the end: rewind it. */
	if (lseek(ifd, 0, SEEK_SET) < 0) {
		pr_perror("Can't rewind the tmpfs content image");
		close(dfd);
		return -1;
	}

	lname[0] = '\0';
	while (read(ifd, hdr, sizeof(hdr)) == sizeof(hdr)) {
		/* The end of the archive: one or two zero blocks. */
		if (hdr[0] == '\0')
			break;

		size = tar_octal(hdr + 124, 12);
		uid = tar_octal(hdr + 108, 8);
		gid = tar_octal(hdr + 116, 8);
		typeflag = hdr[156];

		if (typeflag == 'L') {
			/* The GNU long name of the next entry: read it. */
			size_t rd = size < sizeof(lname) - 1 ? size : sizeof(lname) - 1;

			if (read(ifd, lname, rd) < 0)
				break;
			lname[rd] = '\0';
			lseek(ifd, round_up(size, 512) - rd, SEEK_CUR);
			continue;
		}

		if (typeflag == '0' || typeflag == '\0' || typeflag == '5' || typeflag == '2') {
			const char *prefix = hdr + 345;

			if (lname[0]) {
				file = lname;
			} else {
				if (prefix[0])
					snprintf(full, sizeof(full), "%.*s/%.*s", 155, prefix, 100, hdr);
				else
					snprintf(full, sizeof(full), "%.*s", 100, hdr);
				file = full[0] == '.' && full[1] == '/' ? full + 2 : full;
			}

			if (file[0] == '.' && file[1] == '/')
				file += 2;

			if (*file) {
				unsigned int tuid = uid, tgid = gid;

				userns_view_id(&tuid, true);
				userns_view_id(&tgid, false);

				if (fchownat(dfd, file, tuid, tgid, AT_SYMLINK_NOFOLLOW) < 0 && errno != ENOENT) {
					pr_warn("Can't set the ownership (%u, %u) of %s in %s: %s\n",
						 tuid, tgid, file, root, strerror(errno));
					ret = -1;
				}
			}
		}

		/* Skip the data of the entry. */
		lseek(ifd, round_up(size, 512), SEEK_CUR);
		lname[0] = '\0';
	}

	close(dfd);
	return ret;
}

/*
 * Restore the content of a tmpfs mounted in a nested mount namespace from
 * its image. The tar runs in the context of the restoring task, i.e. inside
 * the rootfs of the container, where only a busybox one may be available,
 * so the GNU tar only options are not used: the plain extraction of the
 * stored names is fine for the content of a nested mount namespace.
 */
static int nested_restore_tmpfs_content(struct mount_info *mi)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_TMPFS_DEV, O_RSTR, mi->s_dev);
	if (!img)
		return 0;
	if (empty_image(img)) {
		close_image(img);
		img = open_image(CR_FD_TMPFS_IMG, O_RSTR, mi->mnt_id);
		if (!img)
			return 0;
		if (empty_image(img)) {
			/* No content image: keep the freshly mounted empty one. */
			close_image(img);
			return 0;
		}
	}

	ret = cr_system(img_raw_fd(img), -1, -1, "tar",
			(char *[]){ "tar", "--extract", "--directory", mi->ns_mountpoint, NULL }, 0);
	if (!ret)
		ret = nested_fix_tmpfs_ownership(img, mi->ns_mountpoint);
	close_image(img);

	if (ret)
		pr_warn("Can't restore the content of the tmpfs at %s\n", mi->ns_mountpoint);

	return 0;
}

/*
 * Restore the content of the namespaces owned by the nested user
 * namespace of this task: they are created empty at fork and are
 * filled in from their images here.
 */
int nested_ns_child_namespaces(struct pstree_item *item)
{
	struct ns_id *nsid;

	if (!item->parent)
		return 0;

	if (!(rsti(item)->clone_flags & CLONE_NEWUSER)) {
		/*
		 * A task forked from a one outside its user namespace (see
		 * nested_ns_fix_exec_userns): join the one created by the
		 * first task of it, so the namespaces owned by it are
		 * enterable. The ones forked from a task already in it have
		 * inherited the namespace with the fork: they are in it
		 * already, joining it is not allowed.
		 */
		struct pstree_item *parent = item->parent;

		while (parent && !parent->ids)
			parent = parent->parent;

		if (parent && parent->ids && item->ids && root_item->ids &&
		    item->ids->user_ns_id != parent->ids->user_ns_id &&
		    item->ids->user_ns_id != root_item->ids->user_ns_id)
			return nested_ns_join_userns(item);
		return 0;
	}

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

	if (rsti(item)->clone_flags & CLONE_NEWNET) {
		/*
		 * Create our own network namespace, which is owned by
		 * our user namespace, and fill it in from its image,
		 * as the ones created by the root task are owned by
		 * its user namespace.
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

void nested_ns_child_abort(struct pstree_item *item)
{
	if (!item->parent || !(rsti(item)->clone_flags & CLONE_NEWUSER))
		return;

	futex_abort_and_wake(&rsti(item)->userns_maps);
}

bool nested_ns_skip_netns(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;

	if (!nested_ns_enabled() || !item->ids || !item->ids->has_net_ns_id)
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
 * Whether the network namespace is owned by a nested user namespace,
 * i.e. it has to be created by the task which has entered it, and
 * not by the root task.
 */
static unsigned int *own_netns;
static int n_own_netns;

static void collect_own_netns(void)
{
	struct pstree_item *item;

	/*
	 * The network namespace of a task entering a nested user
	 * namespace, if it has its own one, is created by the task
	 * itself on restore.
	 */
	for_each_pstree_item(item) {
		if (!item->parent || !item->ids)
			continue;

		if (!(rsti(item)->clone_flags & CLONE_NEWUSER) || !(rsti(item)->clone_flags & CLONE_NEWNET))
			continue;

		own_netns = xrealloc(own_netns, (n_own_netns + 1) * sizeof(*own_netns));
		if (!own_netns)
			return;
		own_netns[n_own_netns++] = item->ids->net_ns_id;
	}
}

bool nested_ns_own_netns(struct ns_id *nsid)
{
	int i;

	if (!nested_ns_enabled())
		return false;

	if (!own_netns)
		collect_own_netns();

	for (i = 0; i < n_own_netns; i++)
		if (own_netns[i] == nsid->id)
			return true;

	return false;
}

/*
 * Whether the mount namespace is owned by a nested user namespace,
 * i.e. the task which has entered it was born in its own one at
 * fork, and assembles it by itself.
 */
static unsigned int *own_mntns;
static int n_own_mntns;

static void collect_own_mntns(void)
{
	struct pstree_item *item;

	/*
	 * The task entering a nested user namespace with its own
	 * mount namespace is born in a copy of the parent's one,
	 * owned by the new user namespace, and fills it in from
	 * the image by itself.
	 */
	for_each_pstree_item(item) {
		if (!item->parent || !item->ids)
			continue;

		if ((rsti(item)->clone_flags & (CLONE_NEWUSER | CLONE_NEWNS)) != (CLONE_NEWUSER | CLONE_NEWNS))
			continue;

		own_mntns = xrealloc(own_mntns, (n_own_mntns + 1) * sizeof(*own_mntns));
		if (!own_mntns)
			return;
		own_mntns[n_own_mntns++] = item->ids->mnt_ns_id;
	}
}

bool nested_ns_own_mntns(struct ns_id *nsid)
{
	int i;

	if (!nested_ns_enabled())
		return false;

	if (!own_mntns)
		collect_own_mntns();

	for (i = 0; i < n_own_mntns; i++)
		if (own_mntns[i] == nsid->id)
			return true;

	return false;
}

bool nested_ns_skip_mntns(struct pstree_item *item)
{
	/*
	 * The task was born in its own mount namespace at fork,
	 * as its clone flags kept the mount namespace one, so it
	 * is already there and has filled it in by itself.
	 *
	 * A task below the one which has entered the nested user
	 * namespace might have no clone flags of its own (the
	 * boundary task has exited before the dump), but its mount
	 * namespace still differs from the root one.
	 */
	if (!nested_ns_enabled() || !item->parent)
		return false;

	if ((rsti(item)->clone_flags & (CLONE_NEWUSER | CLONE_NEWNS)) == (CLONE_NEWUSER | CLONE_NEWNS))
		return true;

	return item->ids && root_item->ids &&
	       item->ids->mnt_ns_id != root_item->ids->mnt_ns_id;
}

static struct mount_info *match_mi;
static int match_found;

static int uns_match_mountpoint(struct mount_info *mi)
{
	if (!strcmp(mi->ns_mountpoint, match_mi->ns_mountpoint) && mi->s_dev == match_mi->s_dev)
		match_found = 1;

	return 0;
}

/*
 * Whether the mount is inherited from the parent task: the mount
 * namespace of the task is a copy of the parent's one made at fork,
 * which keeps the mounts with the same mountpoint and device.
 */
static bool mount_inherited(struct mount_info *mi, struct mount_info *parent_root)
{
	match_mi = mi;
	match_found = 0;

	if (parent_root)
		mnt_tree_for_each(parent_root, uns_match_mountpoint);

	return match_found;
}

static struct mount_info *parent_tree_root;

/*
 * The uid= and gid= options of a mount are dumped in the view of
 * the user namespace of the dumping criu process, and are not
 * valid in the one of the new mount. Strip them: the mount is
 * done by the same user as the original one, so the ownership
 * of the mount is the same, and the ownership of the files is
 * restored from the image anyway.
 */
static char *strip_id_options(char *options)
{
	char *res, *tok, *save, *p;
	int len;

	if (!options)
		return NULL;

	if (!strstr(options, "uid=") && !strstr(options, "gid="))
		return options;

	res = xmalloc(strlen(options) + 1);
	if (!res)
		return NULL;

	p = res;
	for (tok = strtok_r(options, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (!strncmp(tok, "uid=", 4) || !strncmp(tok, "gid=", 4))
			continue;

		len = strlen(tok);
		if (p != res)
			*p++ = ',';
		memcpy(p, tok, len);
		p += len;
	}
	*p = '\0';

	return res;
}

/*
 * Restore the content of a tmpfs of the nested user namespace. The
 * ownership in the tarball is expressed in the view of the user
 * namespace the dump has run in, which is not ours, so it is not
 * restored: we are the one who has mounted this file system, so the
 * files get the right owner.
 */
static int __maybe_unused uns_restore_tmpfs_content(struct mount_info *mi)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_TMPFS_DEV, O_RSTR, mi->s_dev);
	if (empty_image(img)) {
		close_image(img);
		img = open_image(CR_FD_TMPFS_IMG, O_RSTR, mi->mnt_id);
	}
	if (!img)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return -1;
	}

	ret = cr_system(img_raw_fd(img), -1, -1, "tar",
			(char *[]){ "tar", "--extract", "--gzip", "--no-unquote", "--no-wildcards",
				    "--no-same-owner", "--directory", mi->ns_mountpoint, NULL },
			0);
	close_image(img);

	if (ret) {
		pr_err("Can't restore tmpfs content\n");
		return -1;
	}

	return 0;
}

static int uns_mount_one(struct mount_info *mi)
{
	/*
	 * Only the root filesystem of the nested mount namespace is
	 * considered: the task is born in a copy of the parent's mount
	 * tree, and the mountpoints from the nested image are relative
	 * to the nested root filesystem, which is not the same as the
	 * parent's one. The rest of the mounts of the nested mount
	 * namespace are skipped: they are the ones of an inner
	 * container, and the inner container runtime (e.g. docker)
	 * re-creates them when it runs its containers.
	 */
	if (strcmp(mi->ns_mountpoint, "/") != 0)
		return 0;

	/*
	 * The root mount of the nested mount namespace can be the one
	 * inherited from the parent (e.g. the outer container rootfs,
	 * which is already in the copy of the parent's tree), in
	 * which case there is nothing to mount.
	 */
	if (mount_inherited(mi, parent_tree_root))
		return 0;

	{
		char *opts = strip_id_options(mi->options);
		char *src = mi->source[0] ? mi->source : "none";

		if (mount(src, "/", "overlay", mi->sb_flags, opts) < 0) {
			pr_perror("Can't mount overlay at / (src=%s opts=%s)", src, opts);
			return -1;
		}
	}

	return 0;
}

static int uns_mount_err;

static int __maybe_unused uns_mount_tree(struct mount_info *mi)
{
	if (uns_mount_one(mi)) {
		uns_mount_err = -1;
		return -1;
	}

	return 0;
}

/* Set in the task that was born into a nested mount namespace */
static bool nested_child_mntns;

/*
 * Whether this task, living in a nested user namespace, has to take
 * the root fd of the mount namespace being resolved from the shared
 * fdstore. Opening /proc/<pid>/root of a task from a nested user
 * namespace is not allowed (no capabilities in the parent one), and
 * resolving the file paths would fail in the protected phase.
 */
bool nested_ns_use_fdstore(struct ns_id *nsid)
{
	/*
	 * Any task of the restore may resolve the root of a mount
	 * namespace which is not its own one (e.g. while opening a file
	 * living in it): opening /proc/<pid>/root of a task from a
	 * nested user namespace is not allowed for one which has not
	 * entered it, and the /proc ones of the cache can not be
	 * changed in the protected phase of the restore. The root is
	 * taken from the fdstore instead, where it was put when the
	 * namespace was set up (either by the first task of a nested
	 * one, or by the standard mount restore of the others).
	 */
	if (!nested_ns_enabled() || !nsid || nsid->nd != &mnt_ns_desc)
		return false;

	return nsid->mnt.root_fd_id >= 0;
}

/*
 * The mount namespace of this task was created at fork, as a copy
 * of the parent's one owned by our user namespace. Fill it in from
 * the image: the inherited mounts are already there, the other ones
 * are mounted in place, on top of the inherited ones if needed.
 */

/*
 * The uid= and gid= options of a dump-time mount hold the ids in the
 * view of the user namespace of the dumping criu: they may be not
 * mapped in the nested user namespace the mount is made from, which
 * the kernel rejects. Drop them: the mount is made by the remapped
 * root of the namespace, which owns the files of the mounted one
 * anyway.
 */
static void nested_mount_opts(const char *opts, char *buf, size_t size)
{
	const char *p = opts;
	size_t off = 0;

	buf[0] = '\0';
	if (!opts)
		return;

	while (*p) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);

		if (strncmp(p, "uid=", 4) && strncmp(p, "gid=", 4)) {
			if (off && off + 1 < size)
				buf[off++] = ',';
			if (off + len >= size)
				break;
			memcpy(buf + off, p, len);
			off += len;
			buf[off] = '\0';
		}
		if (!comma)
			break;
		p = comma + 1;
	}
}

int nested_ns_child_mntns(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct ns_id *nsid, *pnsid = NULL;
	int fd, root_fd;

	if (!nested_ns_skip_mntns(item))
		return 0;

	nsid = lookup_ns_by_id(item->ids->mnt_ns_id, &mnt_ns_desc);
	if (!nsid) {
		pr_err("Can't find mntns id %d\n", item->ids->mnt_ns_id);
		return -1;
	}

	/*
	 * Pin the namespace, so that the tasks below can enter it. Only
	 * the first task of the namespace does it: the ones below are
	 * forked from it after the chroot, and their view of /proc is the
	 * one of the root filesystem of the inner container.
	 */
	if (nsid->mnt.nsfd_id < 0) {
		fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("Can't open our mount namespace fd");
			return -1;
		}
		nsid->mnt.nsfd_id = fdstore_add(fd);
		close(fd);
		if (nsid->mnt.nsfd_id < 0) {
			pr_err("Can't add ns fd\n");
			return -1;
		}
	}

	/*
	 * Cache the root fd of the mount namespace of the parent
	 * task, which is where the files of the nested one live.
	 * Opening /proc/<pid>/root of a task from a nested user
	 * namespace is not allowed, and resolving the file paths
	 * would fail in the protected phase (see __mntns_get_root_fd).
	 */
	while (parent && !parent->ids)
		parent = parent->parent;

	if (parent) {
		pnsid = lookup_ns_by_id(parent->ids->mnt_ns_id, &mnt_ns_desc);
		if (!pnsid) {
			pr_err("Can't find parent mntns id %d\n", parent->ids->mnt_ns_id);
			return -1;
		}
	}

	root_fd = pnsid ? fdstore_get(pnsid->mnt.root_fd_id) : -1;
	if (root_fd < 0) {
		pr_err("Can't get the root fd of the parent mntns\n");
		return -1;
	}

	if (mntns_set_root_fd(pnsid->ns_pid, root_fd) < 0) {
		pr_err("Can't cache the parent mntns root fd\n");
		return -1;
	}

	/*
	 * From now on the mounts of a foreign namespace are taken
	 * from the fdstore, and our own ones are resolved via
	 * /proc/self. Pre-install the /proc/self service fd, so
	 * that the latter doesn't happen in the protected phase.
	 *
	 * The pid of the task may not be restored with the original
	 * one: a task of a nested user namespace can not set the pid
	 * of its children. In that case only the /proc/self entry is
	 * pre-installed, as the one of the pid doesn't exist.
	 */
	nested_child_mntns = true;

	fd = open_pid_proc(vpid(item));
	if (fd < 0)
		fd = open_pid_proc(PROC_SELF);
	if (fd < 0) {
		pr_perror("Can't open our /proc/%d nor /proc/self", vpid(item));
		return -1;
	}

	/*
	 * The root filesystem of the nested mount namespace is the
	 * overlayfs one of the inner container, which is already
	 * mounted in the parent's tree (e.g. at
	 * /docker-data/overlay2/<id>/merged of the outer one).
	 * Chroot into it and mount the essential filesystems.
	 */
	if (!(rsti(item)->clone_flags & CLONE_NEWNS)) {
		/*
		 * The task was forked in the mount namespace of its parent:
		 * the first task of the namespace set it up already, and we
		 * were born into a copy of it with the chroot and the
		 * essential mounts in place. Only refresh our own root fd,
		 * so that the file path resolution uses the root of the
		 * inner container. It is opened without O_PATH, as it is
		 * also used as a working directory by the restore.
		 */
		int root_fd = open("/", O_RDONLY | O_CLOEXEC);

		if (root_fd < 0) {
			pr_perror("Can't open our chrooted root fd");
			return -1;
		}
		if (mntns_set_root_fd(nsid->ns_pid, root_fd) < 0) {
			pr_err("Can't set our root fd\n");
			close(root_fd);
			return -1;
		}
		return 0;
	}
	{
		struct mount_info *mi, *root_mi = NULL;
		char rootfs_path[PATH_MAX];
		int found = 0;
#define MAX_BIND_FDS 64
		int bind_fds[MAX_BIND_FDS];
		struct mount_info *bind_mis[MAX_BIND_FDS];
		int n_bind_fds = 0;
		int bi;

		/* Find the root mount of the nested mntns */
		for (mi = nsid->mnt.mntinfo_tree; mi; mi = mi->next) {
			if (!strcmp(mi->ns_mountpoint, "/")) {
				root_mi = mi;
				break;
			}
		}

		if (!root_mi) {
			pr_err("Can't find the root mount of the nested mntns\n");
			return -1;
		}

		/*
		 * The root filesystem of the nested mount namespace is
		 * either the overlayfs one of the inner container, which is
		 * already mounted in the parent's tree (e.g. at
		 * /docker-data/overlay2/<id>/merged of the outer one), or a
		 * bind mount of a directory of the parent's filesystem (the
		 * vfs driver of the inner docker).
		 */
		if (root_mi->root && root_mi->root[0] == '/' && strcmp(root_mi->root, "/")) {
			/*
			 * A bind mount of a directory of the parent's
			 * filesystem (e.g. the one of the vfs driver of the
			 * inner docker): the root is the path of the bound
			 * one in it, and the file system type of the mount
			 * is the one of the underlying one.
			 */
			snprintf(rootfs_path, sizeof(rootfs_path), "%s", root_mi->root);
			found = 1;
		} else {
			/*
			 * The overlayfs of the inner container: find the
			 * same one in the parent's tree by the device
			 * number, it is mounted at a different path there.
			 */
			for (mi = pnsid->mnt.mntinfo_tree; mi; mi = mi->next) {
				if (mi->s_dev == root_mi->s_dev &&
				    mi->fstype->code == FSTYPE__OVERLAYFS) {
					snprintf(rootfs_path, sizeof(rootfs_path), "%s", mi->ns_mountpoint);
					found = 1;
					break;
				}
			}
		}

		if (!found) {
			/*
			 * Fallback: the root mount's source might be the
			 * path of the overlay in the parent's tree.
			 */
			if (root_mi->source[0] == '/') {
				snprintf(rootfs_path, sizeof(rootfs_path), "%s", root_mi->source);
				found = 1;
			}
		}

		if (!found) {
			pr_err("Can't find the rootfs of the nested mntns\n");
			return -1;
		}


		/*
		 * The sources of the bind mounts are the paths in the parent's
		 * filesystems (e.g. the device nodes the runtime of the inner
		 * container has bound from its own /dev, like the /dev/null
		 * one of a docker with userns-remap), so they are only
		 * reachable while the root is still the one of the parent:
		 * they are opened now, and the mounts are made after the
		 * chroot and the essential ones, as the fresh ones (e.g. the
		 * tmpfs on /dev of the inner container) would hide the ones
		 * made under them before.
		 */
		for (mi = nsid->mnt.mntinfo_tree; mi && n_bind_fds < MAX_BIND_FDS; mi = mi->next) {
			char source[PATH_MAX];
			struct stat st;

			if (!strcmp(mi->ns_mountpoint, "/") || !mi->root || !strcmp(mi->root, "/"))
				continue;

			if (stat(mi->root, &st) == 0)
				snprintf(source, sizeof(source), "%s", mi->root);
			else if (stat(mi->ns_mountpoint, &st) == 0)
				/*
				 * The source of the device nodes is the same
				 * path in the view of the parent one.
				 */
				snprintf(source, sizeof(source), "%s", mi->ns_mountpoint);
			else {
				pr_warn("Can't find the source %s of the bind mount %s\n",
					 mi->root, mi->ns_mountpoint);
				continue;
			}

			bind_fds[n_bind_fds] = open(source, O_PATH | O_CLOEXEC);
			if (bind_fds[n_bind_fds] < 0) {
				pr_perror("Can't open the source %s of the bind mount %s\n",
					  source, mi->ns_mountpoint);
				continue;
			}
			bind_mis[n_bind_fds] = mi;
			n_bind_fds++;
		}

		if (chdir(rootfs_path) < 0) {
			pr_perror("Can't chdir to %s", rootfs_path);
			return -1;
		}
		if (chroot(rootfs_path) < 0) {
			pr_perror("Can't chroot to %s", rootfs_path);
			return -1;
		}
		if (chdir("/") < 0) {
			pr_perror("Can't chdir to /");
			return -1;
		}

		/* Mount the essential filesystems of the inner container */
		for (mi = nsid->mnt.mntinfo_tree; mi; mi = mi->next) {
			struct mount_info *pmi;
			bool inherited = false;

			if (!strcmp(mi->ns_mountpoint, "/"))
				continue;

			/*
			 * The namespace was created at fork as a copy of the
			 * parent one, so the mounts which were already there
			 * at the copy are inherited with it. Mounting a fresh
			 * one on top of an inherited would hide the files of
			 * the original, e.g. of the tmpfs of the container
			 * the nested one was created in: a mount which is in
			 * the parent namespace as well was inherited, and is
			 * already in place in the fresh copy of it.
			 */
			/*
			 * The parent task may be recorded in the same mount
			 * namespace (e.g. the one of an inner runtime, which has
			 * entered the one of the container it has created):
			 * nothing is inherited then, as the fresh copy the
			 * namespace is created from at fork is the one of the
			 * parent's own restore, which has the mounts set up in
			 * its own way.
			 *
			 * Nothing is inherited under the root filesystem of the
			 * inner container either: the mounts of the fresh copy
			 * of the parent's one are at the paths of the parent, and
			 * the chroot into the rootfs makes them unreachable —
			 * everything is mounted fresh inside it.
			 */
			if (pnsid == nsid || strcmp(rootfs_path, "/"))
				inherited = false;
			else
				for (pmi = pnsid ? pnsid->mnt.mntinfo_tree : NULL; pmi; pmi = pmi->next) {
					if (!strcmp(pmi->ns_mountpoint, mi->ns_mountpoint) && pmi->s_dev == mi->s_dev) {
						inherited = true;
						break;
					}
				}
			if (inherited)
				continue;


			/*
			 * The bind mounts were set up before the chroot: the ones
			 * of the device nodes of the parent's /dev are not found
			 * by the inherited check above, as the parent has them at
			 * the same mount points, but inside the chroot they are
			 * not there.
			 */
			if (mi->root && strcmp(mi->root, "/"))
				continue;

			/* Create the mountpoint if needed */
			mkdirpat(AT_FDCWD, mi->ns_mountpoint, 0755);

			switch (mi->fstype->code) {
			case FSTYPE__PROC:
				if (mount("proc", mi->ns_mountpoint, "proc",
					  mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
					pr_warn("Can't mount proc at %s\n", mi->ns_mountpoint);
				break;
			case FSTYPE__SYSFS:
				if (mount("sysfs", mi->ns_mountpoint, "sysfs",
					  mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
					pr_warn("Can't mount sysfs at %s\n", mi->ns_mountpoint);
				break;
			case FSTYPE__DEVTMPFS:
				if (mount("dev", mi->ns_mountpoint, "devtmpfs",
					  mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
					pr_warn("Can't mount devtmpfs at %s\n", mi->ns_mountpoint);
				break;
			case FSTYPE__DEVPTS: {
				char opts[PATH_MAX];

				nested_mount_opts(mi->options, opts, sizeof(opts));
				if (mount("devpts", mi->ns_mountpoint, "devpts",
					  mi->sb_flags & ~MS_PROPAGATE, opts) < 0)
					pr_warn("Can't mount devpts at %s\n", mi->ns_mountpoint);
				break;
			}
			case FSTYPE__TMPFS: {
				char opts[PATH_MAX];

				nested_mount_opts(mi->options, opts, sizeof(opts));
				if (mount("tmpfs", mi->ns_mountpoint, "tmpfs",
					  mi->sb_flags & ~MS_PROPAGATE, opts) < 0) {
					pr_warn("Can't mount tmpfs at %s\n", mi->ns_mountpoint);
				} else {
					nested_restore_tmpfs_content(mi);
				}
				break;
			}
				break;
			default:
				/*
				 * The other mounts (bind mounts of the
				 * inner container runtime) are skipped:
				 * the inner processes might not find them,
				 * but the essential ones are there.
				 */
				break;
			}
		}

		/*
		 * The bind mounts, with the sources opened before the chroot:
		 * they are mounted by their /proc/self/fd paths, so that the
		 * ones of the parent's filesystems (e.g. the device nodes)
		 * are reachable from inside the root filesystem of the inner
		 * container. Made after the essential ones, as a fresh mount
		 * (e.g. the tmpfs on /dev) would hide the ones under it.
		 */
		for (bi = 0; bi < n_bind_fds; bi++) {
			char target[PATH_MAX];
			char source[64];
			struct stat st;

			mi = bind_mis[bi];
			snprintf(target, sizeof(target), "%s", mi->ns_mountpoint);

			if (fstat(bind_fds[bi], &st) < 0) {
				pr_perror("Can't stat the source of the bind mount %s\n", target);
				close(bind_fds[bi]);
				continue;
			}

			if (S_ISDIR(st.st_mode)) {
				mkdirpat(AT_FDCWD, target, 0755);
			} else {
				int tfd = open(target, O_CREAT | O_EXCL | O_WRONLY, 0644);

				if (tfd >= 0)
					close(tfd);
			}

			snprintf(source, sizeof(source), "/proc/self/fd/%d", bind_fds[bi]);
			if (mount(source, target, NULL, MS_BIND, NULL) < 0)
				pr_warn("Can't bind-mount %s to %s\n", source, target);
			close(bind_fds[bi]);
		}

		/*
		 * Set our own root fd to the chrooted one, so that
		 * the file path resolution uses it and not the one
		 * of the parent, which was cached before the chroot.
		 * The fd is also put into the fdstore, so that the
		 * other tasks of the restore resolve the paths of
		 * this namespace (e.g. the unix socket ones) with
		 * the root of the inner container, and not with
		 * the one of the parent.
		 */
		{
			int root_fd = open("/", O_RDONLY | O_CLOEXEC);

			if (root_fd < 0) {
				pr_perror("Can't open our chrooted root fd");
				return -1;
			}
			/*
			 * The standard input and output may be closed in a task of
			 * the tree (e.g. the inner database daemon detaches them), so
			 * the opened one may be a low fd: those are taken over by the
			 * restorer later, so move it away from that range.
			 */
			if (root_fd <= 2) {
				int moved = fcntl(root_fd, F_DUPFD, 3);

				if (moved < 0) {
					pr_perror("Can't move the root fd away");
					close(root_fd);
					return -1;
				}
				close(root_fd);
				root_fd = moved;
			}
			/*
			 * mntns_set_root_fd() takes the ownership of the fd (it is
			 * dup-ed into the service slot and closed), so keep another
			 * one for the fdstore below.
			 */
			{
				int store_fd = dup(root_fd);

				if (store_fd < 0) {
					pr_perror("Can't dup the chrooted root fd");
					close(root_fd);
					return -1;
				}
				if (mntns_set_root_fd(nsid->ns_pid, root_fd) < 0) {
					pr_err("Can't set our root fd\n");
					close(store_fd);
					return -1;
				}
				{
					int id = fdstore_add(store_fd);

					close(store_fd);
					if (id < 0) {
						pr_err("Can't add the chrooted root fd (errno %d)\n", errno);
						return -1;
					}
					/*
					 * Overwrite the one pinned before the tasks were
					 * forked: it resolves the paths of the root
					 * filesystem, but not the ones under the mounts
					 * set up here (e.g. the device nodes under the
					 * tmpfs on /dev).
					 */
					nsid->mnt.root_fd_id = id;
				}
			}
		}
	}

	return 0;
}

bool nested_ns_cflags_ok(unsigned long cflags)
{
	if (!nested_ns_enabled())
		return false;

	/*
	 * In addition to the nested CLONE_SUBNS namespaces a
	 * sub-task may be created in its own user namespace and,
	 * from inside it, in its own uts namespace, which are
	 * restored when its parent task forks it.
	 */
	return !((cflags & ~(root_ns_mask & CLONE_SUBNS)) &
		 ~(CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWCGROUP));
}
