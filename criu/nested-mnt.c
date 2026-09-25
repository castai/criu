#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "cr_options.h"
#include "imgset.h"
#include "image.h"
#include "pstree.h"
#include "rst_info.h"
#include "namespaces.h"
#include "nested-ns.h"
#include "mount.h"
#include "filesystems.h"
#include "fdstore.h"
#include "servicefd.h"
#include "util.h"

#include "images/mnt.pb-c.h"

/*
 * The mounts of all the namespaces are chained in one list: walking
 * the tree root of a namespace by the next pointers crosses into the
 * mounts of the other ones, so the walks below filter by namespace.
 */
#define for_each_ns_mount(mi, ns)             \
	for (mi = mntinfo; mi; mi = mi->next) \
		if (mi->nsid == (ns))

/*
 * The mount namespaces owned by the nested user namespaces. They are
 * not assembled by the root task like the other ones: a task of a
 * nested user namespace can not enter a mount namespace owned by the
 * root one, and the root task can not create one owned by the nested
 * user namespace before it exists. So the first task of such a
 * namespace is born into a copy of its parent's one (CLONE_NEWNS at
 * the fork with CLONE_NEWUSER), chroots into the root filesystem of
 * the inner container, which is reachable in the parent's tree, and
 * mounts the rest in place. See nested-ns.h.
 */

bool nested_ns_own_mntns(struct ns_id *nsid)
{
	return nsid && nsid->nd == &mnt_ns_desc && nested_ns_owned(nsid);
}

/*
 * Whether the task is in a mount namespace owned by a nested user
 * namespace: either born in it at the fork, or forked from a task
 * already in it. Such a task skips the setns() into it and fills it
 * in (or only sets its root fd) by itself, see nested_ns_child_mntns().
 */
bool nested_ns_skip_mntns(struct pstree_item *item)
{
	struct ns_id *nsid;

	if (!nested_ns_enabled() || !item->parent || !item->ids || !item->ids->has_mnt_ns_id)
		return false;

	nsid = lookup_ns_by_id(item->ids->mnt_ns_id, &mnt_ns_desc);
	return nested_ns_own_mntns(nsid);
}

/*
 * Whether the root fd of the mount namespace being resolved has to
 * come from the fdstore. Opening /proc/<pid>/root of a task from a
 * nested user namespace is not allowed for one which has not entered
 * it, a task of a nested user namespace can not open the one of any
 * other task, and the /proc ones of the cache can not be changed in
 * the protected phase of the restore. The root is taken from the
 * fdstore instead, where it was put when the namespace was set up
 * (either by the first task of a nested one, or by the standard
 * mount restore of the others).
 */
bool nested_ns_use_fdstore(struct ns_id *nsid)
{
	if (!nested_ns_enabled() || !nsid || nsid->nd != &mnt_ns_desc)
		return false;

	if (nsid->mnt.root_fd_id < 0)
		return false;

	return nested_ns_owned(nsid) || nested_ns_task_nested(current);
}

static struct mount_info *root_mount_of(struct ns_id *nsid)
{
	struct mount_info *mi;

	for_each_ns_mount(mi, nsid)
	{
		if (!strcmp(mi->ns_mountpoint, "/"))
			return mi;
	}

	return NULL;
}

/*
 * The path, in the tree of the parent mount namespace, of a directory
 * of a superblock: mi->root is a path inside the superblock of the
 * mount, so the mount of the same superblock in the parent's tree is
 * looked up (the one whose root is the longest prefix of it) and the
 * rest of the path is appended to its mountpoint. E.g. the root
 * filesystem of an inner container is either a bind mount of a
 * directory of the parent's filesystem (the /docker-data/vfs/dir/<id>
 * of the vfs driver of an inner docker), or the same overlay mounted
 * at a different path (/docker-data/overlay2/<id>/merged).
 */
static int resolve_in_parent(struct ns_id *pnsid, struct mount_info *mi, char *buf, size_t size)
{
	struct mount_info *pmi, *best = NULL;
	size_t best_len = 0;
	const char *rel;

	if (!mi->root)
		return -1;

	for_each_ns_mount(pmi, pnsid)
	{
		size_t len;

		if (pmi->s_dev != mi->s_dev || !pmi->root)
			continue;

		if (!strcmp(pmi->root, "/")) {
			len = 0;
		} else {
			len = strlen(pmi->root);
			if (strncmp(mi->root, pmi->root, len) || (mi->root[len] != '/' && mi->root[len] != '\0'))
				continue;
		}

		if (!best || len > best_len) {
			best = pmi;
			best_len = len;
		}
	}

	if (!best)
		return -1;

	rel = mi->root + best_len;
	if (!strcmp(best->ns_mountpoint, "/"))
		snprintf(buf, size, "%s", *rel ? rel : "/");
	else
		snprintf(buf, size, "%s%s", best->ns_mountpoint, rel);

	return 0;
}

static int nested_rootfs_path(struct ns_id *nsid, struct ns_id *pnsid, char *buf, size_t size)
{
	struct mount_info *root_mi = root_mount_of(nsid);

	if (!root_mi) {
		pr_err("Can't find the root mount of the nested mntns %d\n", nsid->id);
		return -1;
	}

	/*
	 * The path is resolved against the root fd of the parent mount
	 * namespace by the callers: it may not exist in the mount
	 * namespace of the restoring criu, so it is not stat()ed here.
	 */
	if (!resolve_in_parent(pnsid, root_mi, buf, size))
		return 0;

	/* The source of the root mount might be its path in the parent's tree. */
	if (root_mi->source && root_mi->source[0] == '/') {
		snprintf(buf, size, "%s", root_mi->source);
		return 0;
	}

	pr_err("Can't find the rootfs of the nested mntns %d (root %s, dev %#x) in the parent's tree\n", nsid->id,
	       root_mi->root, root_mi->s_dev);
	return -1;
}

/*
 * Pin the root fds of the nested mount namespaces into the fdstore
 * before any task of the tree is forked: the file ones (e.g. the unix
 * socket ones) of a task restoring early may be resolved in one of them,
 * and the first task of the namespace forks too late to have it pinned
 * in time.
 *
 * It is called from the root task, with the mount namespaces assembled
 * and their root fds set.
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
		char rootfs_path[PATH_MAX];
		int fd, id;

		if (!nested_ns_own_mntns(nsid) || nsid->mnt.root_fd_id >= 0)
			continue;

		if (nested_rootfs_path(nsid, root_ns, rootfs_path, sizeof(rootfs_path)))
			return -1;

		/* The rootfs may be the root of the parent's tree itself */
		fd = openat(root_fd, rootfs_path[1] ? rootfs_path + 1 : ".", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("Can't open the rootfs %s of the nested mntns %d", rootfs_path, nsid->id);
			return -1;
		}

		id = fdstore_add(fd);
		close(fd);
		if (id < 0) {
			pr_err("Can't add the root fd of the nested mntns %d\n", nsid->id);
			return -1;
		}

		nsid->mnt.root_fd_id = id;
		pr_debug("Pinned the root fd of the nested mntns %d (fdstore id %d)\n", nsid->id, id);
	}

	return 0;
}

/*
 * The tmpfs content of a nested mount namespace is extracted by the
 * task living in it, inside the root filesystem of the inner
 * container, where only a busybox tar may be available: the GNU
 * sparse format is not used for such archives.
 */
bool nested_ns_tmpfs_plain(struct mount_info *pm)
{
	return pm && nested_ns_owned(pm->nsid);
}

/*
 * Whether a tmpfs archive is gzip-ed, from its content: 1 yes, 0 no,
 * -1 unknown (the image is not seekable, e.g. streamed).
 */
int tmpfs_img_is_gzip(struct cr_img *img)
{
	unsigned char magic[2];

	if (pread(img_raw_fd(img), magic, sizeof(magic), 0) != sizeof(magic))
		return -1;

	return magic[0] == 0x1f && magic[1] == 0x8b;
}

/*
 * The numeric ids of a tar (ustar) archive entry are stored in the
 * octal notation, or in the GNU base-256 one for the big values.
 */
static unsigned long tar_number(const unsigned char *p, int len)
{
	unsigned long v = 0;
	int i;

	if (p[0] & 0x80) {
		v = p[0] & 0x7f;
		for (i = 1; i < len; i++)
			v = (v << 8) | p[i];
		return v;
	}

	for (i = 0; i < len && p[i] >= '0' && p[i] <= '7'; i++)
		v = v * 8 + (p[i] - '0');

	return v;
}

/*
 * The archive of the tmpfs content is created in the context of the
 * dumping criu, so the ids of its entries are the ones of the root
 * task's user namespace view. The task restoring the content of a
 * tmpfs of a nested user namespace runs in it: the tar of an inner
 * container (a busybox one, normally) can not set such ids, as they
 * are not mapped in it, and the extracted files end up owned by
 * itself. Walk the archive here and fix the ownership of the
 * extracted files with the ids translated to the view of the current
 * user namespace.
 */
static int fix_tmpfs_ownership(struct cr_img *img, const char *root)
{
	unsigned char hdr[512];
	char full[512], lname[PATH_MAX];
	const char *file;
	int ifd = img_raw_fd(img), dfd;
	unsigned long size;
	unsigned int uid, gid;
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

		size = tar_number(hdr + 124, 12);
		uid = tar_number(hdr + 108, 8);
		gid = tar_number(hdr + 116, 8);
		typeflag = hdr[156];

		if (typeflag == 'L' || typeflag == 'K') {
			/* The GNU long name (or link target) of the next entry. */
			size_t rd = size < sizeof(lname) - 1 ? size : sizeof(lname) - 1;

			if (typeflag == 'L') {
				if (read(ifd, lname, rd) != rd)
					break;
				lname[rd] = '\0';
				lseek(ifd, round_up(size, 512) - rd, SEEK_CUR);
			} else {
				lseek(ifd, round_up(size, 512), SEEK_CUR);
			}
			continue;
		}

		if (typeflag == '0' || typeflag == '\0' || typeflag == '5' || typeflag == '2') {
			const char *prefix = (const char *)hdr + 345;

			if (lname[0]) {
				file = lname;
			} else {
				if (prefix[0])
					snprintf(full, sizeof(full), "%.*s/%.*s", 155, prefix, 100, (const char *)hdr);
				else
					snprintf(full, sizeof(full), "%.*s", 100, (const char *)hdr);
				file = full;
			}

			if (file[0] == '.' && file[1] == '/')
				file += 2;

			if (*file) {
				unsigned int tuid = uid, tgid = gid;

				nested_ns_view_id(&tuid, true);
				nested_ns_view_id(&tgid, false);

				if (fchownat(dfd, file, tuid, tgid, AT_SYMLINK_NOFOLLOW) < 0 && errno != ENOENT) {
					pr_warn("Can't set the ownership (%u, %u) of %s in %s: %s\n", tuid, tgid, file, root,
						strerror(errno));
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
 * so the GNU tar only options are not used.
 */
static int restore_tmpfs_content(struct mount_info *mi)
{
	struct cr_img *img;
	int ret, gz;

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

	/*
	 * The ids of the archive are not mapped in our user namespace
	 * (see fix_tmpfs_ownership()): the tar must not try to set them.
	 */
	gz = tmpfs_img_is_gzip(img);
	if (gz > 0)
		ret = cr_system(img_raw_fd(img), -1, -1, "tar",
				(char *[]){ "tar", "--extract", "--gzip", "--no-same-owner", "--directory",
					    mi->ns_mountpoint, NULL },
				0);
	else
		ret = cr_system(img_raw_fd(img), -1, -1, "tar",
				(char *[]){ "tar", "--extract", "--no-same-owner", "--directory", mi->ns_mountpoint,
					    NULL },
				0);
	if (!ret)
		ret = fix_tmpfs_ownership(img, mi->ns_mountpoint);
	close_image(img);

	if (ret)
		pr_warn("Can't restore the content of the tmpfs at %s\n", mi->ns_mountpoint);

	return 0;
}

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

/*
 * The source of a bind mount of the nested namespace, as a path in
 * the tree of the parent one (see resolve_in_parent()).
 */
static int resolve_bind_source(struct ns_id *pnsid, struct mount_info *mi, char *buf, size_t size)
{
	struct stat st;

	if (!resolve_in_parent(pnsid, mi, buf, size)) {
		if (stat(buf, &st) == 0)
			return 0;
		pr_warn("The source %s of the bind mount %s is not there\n", buf, mi->ns_mountpoint);
	}

	/*
	 * The mount of the source superblock is not in the parent's
	 * tree (e.g. it is bound from the tree of an outer namespace):
	 * try the paths of the root and of the mountpoint as they are.
	 */
	if (stat(mi->root, &st) == 0) {
		snprintf(buf, size, "%s", mi->root);
		return 0;
	}
	if (stat(mi->ns_mountpoint, &st) == 0) {
		pr_warn("Binding %s from the same path of the parent mount namespace\n", mi->ns_mountpoint);
		snprintf(buf, size, "%s", mi->ns_mountpoint);
		return 0;
	}

	pr_warn("Can't find the source %s of the bind mount %s\n", mi->root, mi->ns_mountpoint);
	return -1;
}

static bool mount_inherited(struct ns_id *pnsid, struct mount_info *mi)
{
	struct mount_info *pmi;

	for_each_ns_mount(pmi, pnsid)
	{
		if (!strcmp(pmi->ns_mountpoint, mi->ns_mountpoint) && pmi->s_dev == mi->s_dev)
			return true;
	}

	return false;
}

/*
 * The root fd of the current task: opened without O_PATH, as it is
 * also used as a working directory by the restore, and moved away
 * from the standard io range, which the restorer takes over later.
 */
static int open_own_root(void)
{
	int fd = open("/", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		pr_perror("Can't open our chrooted root fd");
		return -1;
	}

	if (fd <= 2) {
		int moved = fcntl(fd, F_DUPFD, 3);

		close(fd);
		if (moved < 0) {
			pr_perror("Can't move the root fd away");
			return -1;
		}
		fd = moved;
	}

	return fd;
}

#define MAX_BIND_FDS 64

/*
 * The mount namespace of this task was created at fork, as a copy of
 * the parent's one owned by our user namespace. Fill it in from the
 * image: the root filesystem of the inner container is reached in
 * the parent's tree and chroot-ed into (the mounts of the copy are
 * locked in the user namespace, so the root can not be pivoted or
 * stacked over), the essential filesystems are mounted fresh in it,
 * and the bind mounts are replayed from fds opened before the chroot.
 *
 * As it is a chroot and not a root of the namespace, the tasks of the
 * inner container have a /proc/<pid>/root which is not the root of
 * their mount namespace: the root fd of the namespace is taken from
 * the fdstore (see nested_ns_use_fdstore()), never from there.
 */
int nested_ns_child_mntns(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct ns_id *nsid, *pnsid = NULL;
	struct mount_info *mi;
	char rootfs_path[PATH_MAX];
	int bind_fds[MAX_BIND_FDS];
	struct mount_info *bind_mis[MAX_BIND_FDS];
	int n_bind_fds = 0, bi, fd, root_fd, store_fd, id;

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
	fd = open_pid_proc(nested_ns_pid_not_visible(item) ? PROC_SELF : vpid(item));
	if (fd < 0) {
		pr_perror("Can't open our /proc entry");
		return -1;
	}

	if (!(rsti(item)->clone_flags & CLONE_NEWNS)) {
		/*
		 * The task was forked in the mount namespace of its parent:
		 * the first task of the namespace set it up already, and we
		 * were born into a copy of it with the chroot and the
		 * essential mounts in place. Only refresh our own root fd,
		 * so that the file path resolution uses the root of the
		 * inner container.
		 */
		root_fd = open_own_root();
		if (root_fd < 0)
			return -1;
		if (mntns_set_root_fd(nsid->ns_pid, root_fd) < 0) {
			pr_err("Can't set our root fd\n");
			return -1;
		}
		return 0;
	}

	if (nested_rootfs_path(nsid, pnsid, rootfs_path, sizeof(rootfs_path)))
		return -1;

	pr_info("Assembling the nested mntns %d in place, rootfs %s in the parent mntns %d\n", nsid->id, rootfs_path,
		pnsid->id);

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
	for_each_ns_mount(mi, nsid)
	{
		char source[PATH_MAX];

		if (!strcmp(mi->ns_mountpoint, "/") || !mi->root || !strcmp(mi->root, "/"))
			continue;

		if (n_bind_fds >= MAX_BIND_FDS) {
			pr_warn("Too many bind mounts in the nested mntns %d: %s is skipped\n", nsid->id,
				mi->ns_mountpoint);
			continue;
		}

		if (resolve_bind_source(pnsid, mi, source, sizeof(source)))
			continue;

		bind_fds[n_bind_fds] = open(source, O_PATH | O_CLOEXEC);
		if (bind_fds[n_bind_fds] < 0) {
			pr_perror("Can't open the source %s of the bind mount %s", source, mi->ns_mountpoint);
			continue;
		}
		bind_mis[n_bind_fds] = mi;
		n_bind_fds++;
	}

	if (chdir(rootfs_path) < 0) {
		pr_perror("Can't chdir to %s", rootfs_path);
		goto err_binds;
	}
	if (chroot(rootfs_path) < 0) {
		pr_perror("Can't chroot to %s", rootfs_path);
		goto err_binds;
	}
	if (chdir("/") < 0) {
		pr_perror("Can't chdir to /");
		goto err_binds;
	}

	/* Mount the essential filesystems of the inner container */
	for_each_ns_mount(mi, nsid)
	{
		char opts[PATH_MAX];

		if (!strcmp(mi->ns_mountpoint, "/"))
			continue;

		/*
		 * The bind mounts are made below, from the fds opened
		 * before the chroot.
		 */
		if (mi->root && strcmp(mi->root, "/"))
			continue;

		/*
		 * The namespace was created at fork as a copy of the
		 * parent's one, so the mounts which were there at the
		 * copy are inherited with it: a mount at the same path
		 * and of the same superblock in the parent's tree is
		 * already in place, mounting a fresh one over it would
		 * hide its content (e.g. the device nodes of /dev).
		 * Nothing is inherited under the root filesystem of an
		 * inner container (the chroot makes the copied mounts
		 * unreachable), nor when the parent task is recorded in
		 * the same namespace (the copy comes from its own restore).
		 */
		if (pnsid != nsid && !strcmp(rootfs_path, "/") && mount_inherited(pnsid, mi)) {
			pr_info("\tThe %s mount at %s is inherited from the parent mntns\n", mi->fstype->name,
				mi->ns_mountpoint);
			continue;
		}

		pr_info("\tMounting %s at %s\n", mi->fstype->name, mi->ns_mountpoint);

		mkdirpat(AT_FDCWD, mi->ns_mountpoint, 0755);

		switch (mi->fstype->code) {
		case FSTYPE__PROC:
			if (mount("proc", mi->ns_mountpoint, "proc", mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
				pr_warn("Can't mount proc at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__SYSFS:
			if (mount("sysfs", mi->ns_mountpoint, "sysfs", mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
				pr_warn("Can't mount sysfs at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__DEVTMPFS:
			if (mount("dev", mi->ns_mountpoint, "devtmpfs", mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
				pr_warn("Can't mount devtmpfs at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__DEVPTS:
			nested_mount_opts(mi->options, opts, sizeof(opts));
			if (mount("devpts", mi->ns_mountpoint, "devpts", mi->sb_flags & ~MS_PROPAGATE, opts) < 0)
				pr_warn("Can't mount devpts at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__MQUEUE:
			if (mount("mqueue", mi->ns_mountpoint, "mqueue", mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
				pr_warn("Can't mount mqueue at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__CGROUP2:
			/* Mounted from inside our cgroup namespace: its root is the one of the inner container */
			if (mount("cgroup2", mi->ns_mountpoint, "cgroup2", mi->sb_flags & ~MS_PROPAGATE, NULL) < 0)
				pr_warn("Can't mount cgroup2 at %s\n", mi->ns_mountpoint);
			break;
		case FSTYPE__CGROUP:
			if (mount("cgroup", mi->ns_mountpoint, "cgroup", mi->sb_flags & ~MS_PROPAGATE, mi->options) < 0)
				pr_warn("Can't mount cgroup (%s) at %s\n", mi->options, mi->ns_mountpoint);
			break;
		case FSTYPE__TMPFS:
			nested_mount_opts(mi->options, opts, sizeof(opts));
			if (mount("tmpfs", mi->ns_mountpoint, "tmpfs", mi->sb_flags & ~MS_PROPAGATE, opts) < 0)
				pr_warn("Can't mount tmpfs at %s\n", mi->ns_mountpoint);
			else
				restore_tmpfs_content(mi);
			break;
		default:
			/*
			 * The other mounts of the inner container are not
			 * re-created (yet): the essential ones are there.
			 */
			pr_warn("The %s mount at %s of the nested mntns %d is not restored\n", mi->fstype->name,
				mi->ns_mountpoint, nsid->id);
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
		char source[64];
		struct stat st;

		mi = bind_mis[bi];

		if (fstat(bind_fds[bi], &st) < 0) {
			pr_perror("Can't stat the source of the bind mount %s", mi->ns_mountpoint);
			close(bind_fds[bi]);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			mkdirpat(AT_FDCWD, mi->ns_mountpoint, 0755);
		} else {
			int tfd = open(mi->ns_mountpoint, O_CREAT | O_EXCL | O_WRONLY, 0644);

			if (tfd >= 0)
				close(tfd);
		}

		snprintf(source, sizeof(source), "/proc/self/fd/%d", bind_fds[bi]);
		pr_info("\tBind-mounting %s (%s) at %s\n", source, mi->root, mi->ns_mountpoint);
		if (mount(source, mi->ns_mountpoint, NULL, MS_BIND, NULL) < 0)
			pr_warn("Can't bind-mount %s to %s\n", source, mi->ns_mountpoint);
		close(bind_fds[bi]);
	}

	/*
	 * Set our own root fd to the chrooted one, so that the file
	 * path resolution uses it and not the one of the parent,
	 * which was cached before the chroot. The fd is also put into
	 * the fdstore, so that the other tasks of the restore resolve
	 * the paths of this namespace (e.g. the unix socket ones)
	 * with the root of the inner container, and not with the one
	 * of the parent. It overwrites the one pinned before the
	 * tasks were forked (see nested_ns_pin_roots()): that one
	 * resolves the paths of the root filesystem, but not the ones
	 * under the mounts set up here (e.g. the device nodes under
	 * the tmpfs on /dev).
	 */
	root_fd = open_own_root();
	if (root_fd < 0)
		return -1;

	/* mntns_set_root_fd() takes the ownership of the fd: keep another one for the fdstore. */
	store_fd = dup(root_fd);
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

	id = fdstore_add(store_fd);
	close(store_fd);
	if (id < 0) {
		pr_err("Can't add the chrooted root fd\n");
		return -1;
	}
	nsid->mnt.root_fd_id = id;
	pr_info("The root fd of the nested mntns %d is the fdstore id %d\n", nsid->id, id);

	return 0;

err_binds:
	for (bi = 0; bi < n_bind_fds; bi++)
		close(bind_fds[bi]);
	return -1;
}
