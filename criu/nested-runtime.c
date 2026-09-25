#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "cr_options.h"
#include "pstree.h"
#include "namespaces.h"
#include "nested-ns.h"
#include "xmalloc.h"
#include "servicefd.h"
#include "util.h"

#include "images/userns.pb-c.h"

/*
 * Glue for the container runtimes running inside the restored tree
 * (e.g. the runc of a docker-in-docker). Nothing here is needed by
 * the restore itself: it makes the restored inner containers usable
 * by their runtime afterwards, and works around the image files
 * being unreadable by the remapped roots of the nested user
 * namespaces. Candidates for a post-restore action script or a
 * plugin. See nested-ns.h.
 */

/*
 * The checkpoint image files are owned by the root which has dumped
 * them, and a task entering a nested user namespace runs as the
 * remapped user on the node, so it can't read them. Make them readable
 * for the time of the restore, once, from the root task: the files
 * are handed to the remapped root of the nested user namespaces when
 * all of them map their uid 0 to the same user, otherwise they are
 * made readable for everybody. The original owner and mode of each
 * file are recorded, and put back at the end of the restore.
 */
struct img_perm {
	struct img_perm *next;
	char *path;
	uid_t uid;
	gid_t gid;
	mode_t mode;
};

static struct img_perm *img_perms;
static uid_t img_uid = (uid_t)-1;
static gid_t img_gid = (gid_t)-1;

static bool map_root(UidGidExtent **exts, int n, unsigned int *out)
{
	int i;

	for (i = 0; i < n; i++) {
		if (exts[i]->first == 0 && exts[i]->count > 0) {
			*out = exts[i]->lower_first;
			return true;
		}
	}

	return false;
}

/*
 * The user the uid 0 of the nested user namespaces is mapped to, when
 * it is the same one for all of them. The maps are dumped in the view
 * of the dumping criu, which is the one of the node.
 */
static int nested_roots_user(void)
{
	struct ns_id *ns;
	bool first = true;

	for (ns = ns_ids; ns; ns = ns->next) {
		UsernsEntry *e = NULL;
		unsigned int uid, gid;
		bool ok;

		if (ns->nd != &user_ns_desc || !nested_ns_owned(ns))
			continue;

		if (nested_ns_read_userns_img(ns->id, &e))
			return -1;

		ok = map_root(e->uid_map, e->n_uid_map, &uid) && map_root(e->gid_map, e->n_gid_map, &gid);
		userns_entry__free_unpacked(e, NULL);
		if (!ok)
			return -1;

		if (first) {
			img_uid = uid;
			img_gid = gid;
			first = false;
		} else if (img_uid != uid || img_gid != gid) {
			return -1;
		}
	}

	return first ? -1 : 0;
}

static int image_open_one(int dirfd, const char *name, const struct stat *sb)
{
	struct img_perm *p;
	mode_t mode = sb->st_mode & ~S_IFMT, want;
	int ret;

	if (img_uid != (uid_t)-1) {
		/* The remapped root reads (and searches) as the owner. */
		want = mode | S_IRUSR | (S_ISDIR(sb->st_mode) ? S_IXUSR : 0);
		if (sb->st_uid == img_uid && sb->st_gid == img_gid && want == mode)
			return 0;
	} else {
		want = mode | S_IRUSR | S_IRGRP | S_IROTH | (S_ISDIR(sb->st_mode) ? S_IXUSR | S_IXGRP | S_IXOTH : 0);
		if (want == mode)
			return 0;
	}

	p = xmalloc(sizeof(*p));
	if (!p)
		return -1;
	p->path = xstrdup(name);
	if (!p->path) {
		xfree(p);
		return -1;
	}
	p->uid = sb->st_uid;
	p->gid = sb->st_gid;
	p->mode = mode;
	p->next = img_perms;
	img_perms = p;

	if (img_uid != (uid_t)-1)
		ret = fchownat(dirfd, name, img_uid, img_gid, AT_SYMLINK_NOFOLLOW) || fchmodat(dirfd, name, want, 0);
	else
		ret = fchmodat(dirfd, name, want, 0);
	if (ret)
		pr_warn("Can't make the image file %s readable: %s\n", name, strerror(errno));

	return 0;
}

/*
 * The image directory is flat: its entries are walked relative to
 * the directory fd of the images, as the current directory of the
 * root task is not the one criu was started in any more.
 */
static int images_open_all(int dirfd)
{
	struct stat st;
	struct dirent *de;
	DIR *d;
	int fd, ret = 0;

	if (fstat(dirfd, &st) == 0 && image_open_one(dirfd, ".", &st))
		return -1;

	fd = dup(dirfd);
	if (fd < 0)
		return -1;
	d = fdopendir(fd);
	if (!d) {
		close(fd);
		return -1;
	}

	rewinddir(d);
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (fstatat(dirfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
			continue;
		if (!S_ISREG(st.st_mode))
			continue;
		if (image_open_one(dirfd, de->d_name, &st)) {
			ret = -1;
			break;
		}
	}

	closedir(d);
	return ret;
}

int nested_ns_images_open(void)
{
	int dirfd;

	if (!nested_ns_enabled())
		return 0;

	dirfd = get_service_fd(IMG_FD_OFF);
	if (dirfd < 0)
		return 0;

	if (nested_roots_user()) {
		img_uid = img_gid = (uid_t)-1;
		pr_warn("Making the image files readable by everybody for the time of the restore\n");
	} else {
		pr_warn("Handing the image files to the user %u:%u for the time of the restore\n", img_uid, img_gid);
	}

	if (images_open_all(dirfd))
		pr_warn("Can't make the image directory readable\n");

	return 0;
}

void nested_ns_images_restore(void)
{
	struct img_perm *p, *next;
	int dirfd = get_service_fd(IMG_FD_OFF);

	for (p = img_perms; p; p = next) {
		next = p->next;
		if (dirfd < 0 || fchownat(dirfd, p->path, p->uid, p->gid, AT_SYMLINK_NOFOLLOW) ||
		    fchmodat(dirfd, p->path, p->mode, 0))
			pr_warn("Can't put back the permissions of the image file %s: %s\n", p->path, strerror(errno));
		xfree(p->path);
		xfree(p);
	}
	img_perms = NULL;
}

/*
 * The start time of a process, as it is recorded in its /proc stat:
 * the identifier of the boot of the running kernel, which the runtimes
 * (e.g. runc) use to tell a process from a reused pid.
 */
static unsigned long proc_starttime(const char *proc_root, pid_t pid)
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

/*
 * The root filesystem of the container is mounted at the path
 * recorded in its state: the processes of it are chrooted into it.
 * The ones of an exec are chrooted the same way by the runtime, from
 * inside the user namespace of the container: the search permission
 * is needed on the whole path, but the storage of a remapped user is
 * owned by the root of the outer container without one for the
 * others, and the capabilities of the user namespace of the container
 * do not cover the files of the outer root. Add the permission on the
 * path components: we run as the root of the outer container here.
 * The path comes from the state file of the inner runtime.
 */
static void open_rootfs_path(const char *rpath)
{
	size_t plen = strlen(rpath), i;

	for (i = 1; i <= plen; i++) {
		struct stat st;
		char comp[PATH_MAX];

		if (rpath[i] != '/' && rpath[i] != '\0')
			continue;

		memcpy(comp, rpath, i);
		comp[i] = '\0';
		if (stat(comp, &st) == 0 && S_ISDIR(st.st_mode) && !(st.st_mode & S_IXOTH)) {
			pr_warn("Adding the search permission for everybody on %s\n", comp);
			if (chmod(comp, st.st_mode | S_IXOTH) < 0)
				pr_warn("Can't add the search permission on %s\n", comp);
		}
	}
}

static int patch_state_json(const char *proc_root, const char *path)
{
	char *buf, *start_f, *pid_f, *root_f, *end, *out = NULL;
	unsigned long st;
	pid_t pid;
	int fd, n, len, ret = 0;
	const size_t max = 32768;

	fd = open(path, O_RDWR);
	if (fd < 0)
		return 0;

	buf = xmalloc(max);
	if (!buf) {
		close(fd);
		return -1;
	}

	do {
		n = read(fd, buf, max - 1);
	} while (n < 0 && errno == EINTR);
	if (n <= 0)
		goto out;
	if (n == max - 1) {
		/* The state file is too large for the buffer: leave it as it is. */
		pr_warn("The runtime state file %s is too large\n", path);
		goto out;
	}
	buf[n] = '\0';

	pid_f = strstr(buf, "\"init_process_pid\":");
	if (!pid_f)
		goto out;
	pid = strtoul(pid_f + sizeof("\"init_process_pid\":") - 1, NULL, 10);

	start_f = strstr(buf, "\"init_process_start\":");
	if (!start_f)
		goto out;

	st = proc_starttime(proc_root, pid);
	if (!st) {
		/* The init process is not visible: leave the state as it is. */
		goto out;
	}

	end = start_f + sizeof("\"init_process_start\":") - 1;
	while (*end >= '0' && *end <= '9')
		end++;

	root_f = strstr(buf, "\"rootfs\":\"");
	if (root_f) {
		char rpath[PATH_MAX];
		size_t plen = 0;

		root_f += sizeof("\"rootfs\":\"") - 1;
		while (root_f[plen] && root_f[plen] != '"' && plen < sizeof(rpath) - 1) {
			rpath[plen] = root_f[plen];
			plen++;
		}
		rpath[plen] = '\0';
		open_rootfs_path(rpath);
	}

	out = xmalloc(n + 32);
	if (!out) {
		ret = -1;
		goto out;
	}
	len = snprintf(out, (start_f - buf) + 48, "%.*s\"init_process_start\":%lu", (int)(start_f - buf), buf, st);
	memcpy(out + len, end, buf + n - end);
	len += buf + n - end;

	/*
	 * The new number may be shorter than the old one: the file is
	 * truncated to the new content, or a trailing piece of the old
	 * one would make it invalid.
	 */
	if (lseek(fd, 0, SEEK_SET) < 0 || write(fd, out, len) != len || ftruncate(fd, len) < 0)
		pr_warn("Can't update the start time of the init process in %s\n", path);
	else
		pr_info("Updated the start time of the init process %d in %s\n", pid, path);

out:
	xfree(out);
	xfree(buf);
	close(fd);
	return ret;
}

static const char *nested_proc_root = "/proc";

static int state_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	size_t len = strlen(fpath);

	if (typeflag != FTW_F || len < 11 || strcmp(fpath + len - 11, "/state.json"))
		return 0;

	return patch_state_json(nested_proc_root, fpath);
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
	 * launching criu one, which sees the processes in the pid
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

	if (nftw("/run", state_cb, 12, FTW_PHYS) < 0)
		pr_warn("Can't walk the runtime state files of /run\n");

	if (mounted) {
		if (umount(proc_root))
			pr_warn("Can't unmount the procfs at %s: %s\n", proc_root, strerror(errno));
		if (rmdir(proc_root))
			pr_warn("Can't remove %s: %s\n", proc_root, strerror(errno));
		nested_proc_root = "/proc";
	}
}
