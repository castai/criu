#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <grp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <net/if.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "Check C/R of a process in a nested user namespace";
const char *test_author = "CAST AI";

/*
 * The test emulates a docker-in-docker (dind) workload:
 *
 *   - the root task lives in its own user namespace (A), like a
 *     container with a user namespace mapping,
 *   - the root task starts a child which enters a user namespace (B)
 *     nested inside A, like a container spawned by a dind daemon.
 *
 * The child maps its ids to a sub-id block of A and verifies its ids,
 * id mappings and the nested userns relationship are preserved by C/R.
 */

#define MARKER_FILE "userns_nested.dat"
#define MARKER_DATA "userns_nested"

enum {
	TEST_FORKED,
	TEST_UNSHARED,
	TEST_MAPPED,
	TEST_READY,
	TEST_CHECK,
	TEST_EXIT,
};

struct id_extent {
	unsigned int first;
	unsigned int lower_first;
	unsigned int count;
};

/* clang-format off */
struct shared {
	futex_t fstate;
	int child_ret;
	struct id_extent uid_ext;
	struct id_extent gid_ext;
	char uid_map_before[256];
	char gid_map_before[256];
	char parent_ns_before[64];
	char child_ns_after[64];
} *sh;
/* clang-format on */

static int read_file_text(const char *path, char *buf, int size)
{
	int fd, len;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	len = read(fd, buf, size - 1);
	close(fd);
	if (len < 0) {
		pr_perror("Can't read %s", path);
		return -1;
	}

	buf[len] = '\0';
	return 0;
}

static int parse_map_extents(const char *path, struct id_extent *exts, int max)
{
	char buf[4096];
	char *line, *save;
	int nr = 0;

	if (read_file_text(path, buf, sizeof(buf)))
		return -1;

	for (line = strtok_r(buf, "\n", &save); line && nr < max;
	     line = strtok_r(NULL, "\n", &save)) {
		unsigned int first, lower_first, count;

		if (sscanf(line, "%u %u %u", &first, &lower_first, &count) != 3) {
			pr_err("Bad map line '%s' in %s\n", line, path);
			return -1;
		}

		exts[nr].first = first;
		exts[nr].lower_first = lower_first;
		exts[nr].count = count;
		nr++;
	}

	return nr;
}

/*
 * Pick an id block of the root task's user namespace to be mapped
 * into the nested one. Prefer a block which is not mapped from zero,
 * like the sub-id blocks docker uses for user namespace remapping.
 */
static int pick_extent(const char *path, struct id_extent *ext)
{
	struct id_extent exts[32];
	int nr, i;

	nr = parse_map_extents(path, exts, ARRAY_SIZE(exts));
	if (nr < 0)
		return -1;

	if (nr == 0) {
		pr_err("No extents in %s\n", path);
		return -1;
	}

	*ext = exts[0];
	for (i = 0; i < nr; i++) {
		if (exts[i].first) {
			*ext = exts[i];
			break;
		}
	}

	return 0;
}

static int write_map_file(int pid, const char *name, const char *value)
{
	char path[64];
	int fd, len = strlen(value);

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (write(fd, value, len) != len) {
		pr_perror("Can't write %s", path);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int read_task_ns_user(int pid, char *buf, int size)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);

	if (readlink(path, buf, size - 1) < 0) {
		pr_perror("Can't readlink %s", path);
		return -1;
	}

	return 0;
}

static int check_task_in_nested_userns(int pid)
{
	char parent_ns[64], child_ns[64];
	if (read_task_ns_user(getpid(), parent_ns, sizeof(parent_ns)))
		return -1;

	if (read_task_ns_user(pid, child_ns, sizeof(child_ns)))
		return -1;

	if (!strcmp(parent_ns, child_ns)) {
		pr_err("Task %d is in the same user namespace as the root task\n", pid);
		return -1;
	}

	return 0;
}

static int nested_child(void)
{
	char buf[256];
	int fd;

	if (setgroups(0, NULL) && errno != EPERM) {
		pr_perror("Can't drop supplementary groups");
		goto err;
	}

	/*
	 * Drop to a sub-id of the root task's user namespace, like
	 * runc does before creating a remapped container, so that
	 * the nested user namespace maps us back to uid 0.
	 */
	if (setresgid(sh->gid_ext.first, sh->gid_ext.first, sh->gid_ext.first)) {
		pr_perror("Can't set gid %u", sh->gid_ext.first);
		goto err;
	}

	if (setresuid(sh->uid_ext.first, sh->uid_ext.first, sh->uid_ext.first)) {
		pr_perror("Can't set uid %u", sh->uid_ext.first);
		goto err;
	}

	if (unshare(CLONE_NEWUSER)) {
		pr_perror("Can't unshare user namespace");
		goto err;
	}

	/* our own uts namespace, like an inner container has */
	if (unshare(CLONE_NEWUTS)) {
		pr_perror("Can't unshare uts namespace");
		goto err;
	}

	if (sethostname("nested-uts-host", strlen("nested-uts-host"))) {
		pr_perror("Can't set hostname");
		goto err;
	}

	/* our own mount namespace, filled in after the maps are set */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Can't unshare mnt namespace");
		goto err;
	}

	/* our own network namespace with the loopback up */
	if (unshare(CLONE_NEWNET)) {
		pr_perror("Can't unshare net namespace");
		goto err;
	}

	{
		struct ifreq ifr;
		int sfd = socket(AF_INET, SOCK_DGRAM, 0);

		if (sfd < 0) {
			pr_perror("Can't open socket");
			goto err;
		}

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
		ifr.ifr_flags = IFF_UP | IFF_RUNNING;
		if (ioctl(sfd, SIOCSIFFLAGS, &ifr)) {
			pr_perror("Can't bring lo up");
			close(sfd);
			goto err;
		}
		close(sfd);
	}

	futex_set_and_wake(&sh->fstate, TEST_UNSHARED);
	futex_wait_until(&sh->fstate, TEST_MAPPED);

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids in the nested userns: uid=%d gid=%d\n", getuid(), getgid());
		goto err;
	}

	/*
	 * Mount our own tmpfs on /tmp, like an inner container rootfs.
	 * Our ids are mapped now, so the files we create are owned by
	 * our uid in the nested user namespace.
	 */
	if (mount(NULL, "/tmp", "tmpfs", 0, "size=1m")) {
		pr_perror("Can't mount tmpfs on /tmp");
		goto err;
	}

	{
		int tfd = open("/tmp/nested-mnt-file", O_CREAT | O_RDWR, 0644);

		if (tfd < 0) {
			pr_perror("Can't create /tmp/nested-mnt-file");
			goto err;
		}
		if (write(tfd, "nested-mnt-data", sizeof("nested-mnt-data")) != sizeof("nested-mnt-data")) {
			pr_perror("Can't write /tmp/nested-mnt-file");
			close(tfd);
			goto err;
		}
		close(tfd);
	}

	/* Stash the mappings to compare them after C/R */
	if (read_file_text("/proc/self/uid_map", sh->uid_map_before, sizeof(sh->uid_map_before)))
		goto err;

	if (read_file_text("/proc/self/gid_map", sh->gid_map_before, sizeof(sh->gid_map_before)))
		goto err;

	fd = open(MARKER_FILE, O_CREAT | O_RDWR | O_TRUNC, 0666);
	if (fd < 0) {
		pr_perror("Can't open %s", MARKER_FILE);
		goto err;
	}

	if (write(fd, MARKER_DATA, sizeof(MARKER_DATA)) != sizeof(MARKER_DATA)) {
		pr_perror("Can't write %s", MARKER_FILE);
		close(fd);
		goto err;
	}

	futex_set_and_wake(&sh->fstate, TEST_READY);
	futex_wait_until(&sh->fstate, TEST_CHECK);

	/* Check that C/R kept the nested user namespace intact */
	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids after C/R: uid=%d gid=%d\n", getuid(), getgid());
		goto err;
	}

	if (readlink("/proc/self/ns/user", sh->child_ns_after, sizeof(sh->child_ns_after) - 1) < 0) {
		pr_perror("Can't readlink /proc/self/ns/user");
		goto err;
	}

	{
		struct utsname ubuf;

		if (uname(&ubuf)) {
			pr_perror("Can't uname");
			goto err;
		}
		if (strncmp(ubuf.nodename, "nested-uts-host", sizeof("nested-uts-host") - 1)) {
			pr_err("Hostname lost after C/R: '%s'\n", ubuf.nodename);
			goto err;
		}
	}

	/* /tmp must still be our own tmpfs with our file in it */
	{
		struct stat st2, st3;
		char fbuf[64];
		int tfd, rn;

		if (stat("/", &st2) || stat("/tmp", &st3)) {
			pr_perror("Can't stat / and /tmp");
			goto err;
		}

		if (st2.st_dev == st3.st_dev) {
			pr_err("/tmp is not a separate mount after C/R\n");
			goto err;
		}

		tfd = open("/tmp/nested-mnt-file", O_RDONLY);
		if (tfd < 0) {
			pr_perror("Can't open /tmp/nested-mnt-file");
			goto err;
		}
		rn = read(tfd, fbuf, sizeof(fbuf) - 1);
		close(tfd);
		if (rn != sizeof("nested-mnt-data") || strncmp(fbuf, "nested-mnt-data", sizeof("nested-mnt-data") - 1)) {
			pr_err("Bad /tmp/nested-mnt-file content after C/R\n");
			goto err;
		}
	}

	/* the loopback must be up in our own network namespace */
	{
		struct ifreq ifr;
		int sfd;

		sfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sfd < 0) {
			pr_perror("Can't open socket");
			goto err;
		}

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
		if (ioctl(sfd, SIOCGIFFLAGS, &ifr)) {
			pr_perror("Can't get lo flags");
			close(sfd);
			goto err;
		}
		close(sfd);

		if (!(ifr.ifr_flags & IFF_UP)) {
			pr_err("lo is down after C/R\n");
			goto err;
		}
	}

	if (read_file_text("/proc/self/uid_map", buf, sizeof(buf)))
		goto err;

	if (strcmp(buf, sh->uid_map_before)) {
		pr_err("uid_map changed after C/R: '%s' != '%s'\n", buf, sh->uid_map_before);
		goto err;
	}

	if (read_file_text("/proc/self/gid_map", buf, sizeof(buf)))
		goto err;

	if (strcmp(buf, sh->gid_map_before)) {
		pr_err("gid_map changed after C/R: '%s' != '%s'\n", buf, sh->gid_map_before);
		goto err;
	}

	/* Check the file we created before C/R through the preserved fd */
	if (lseek(fd, 0, SEEK_SET) < 0) {
		pr_perror("Can't lseek %s", MARKER_FILE);
		close(fd);
		goto err;
	}

	if (read(fd, buf, sizeof(MARKER_DATA)) != sizeof(MARKER_DATA) ||
	    strncmp(buf, MARKER_DATA, sizeof(MARKER_DATA))) {
		pr_err("Bad %s content after C/R\n", MARKER_FILE);
		close(fd);
		goto err;
	}

	close(fd);

	return 0;
err:
	/*
	 * Wake up the parent, which is waiting for us, so that a
	 * setup or check failure does not hang the test.
	 */
	sh->child_ret = -1;
	futex_set_and_wake(&sh->fstate, TEST_EXIT);
	return -1;
}

int main(int argc, char **argv)
{
	char buf[256];
	int pid, status;
	int ret = 0;

	sh = mmap(NULL, sizeof(struct shared), PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Can't map shared region");
		exit(1);
	}

	futex_set(&sh->fstate, TEST_FORKED);

	test_init(argc, argv);

	/* Pick sub-id blocks of our user namespace for the nested one */
	if (pick_extent("/proc/self/uid_map", &sh->uid_ext)) {
		fail("Can't pick a uid extent");
		exit(1);
	}

	if (pick_extent("/proc/self/gid_map", &sh->gid_ext)) {
		fail("Can't pick a gid extent");
		exit(1);
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		exit(1);
	} else if (pid == 0) {
		exit(nested_child() ? 1 : 0);
	}

	futex_wait_while_lt(&sh->fstate, TEST_UNSHARED);

	/*
	 * We are in the parent user namespace of the new one, so
	 * we are allowed to fill in its id mappings, like a dind
	 * daemon does for the containers it spawns.
	 */
	if (write_map_file(pid, "setgroups", "deny")) {
		fail("Can't deny setgroups");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->uid_ext.first, sh->uid_ext.count);
	if (write_map_file(pid, "uid_map", buf)) {
		fail("Can't write uid_map");
		exit(1);
	}

	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->gid_ext.first, sh->gid_ext.count);
	if (write_map_file(pid, "gid_map", buf)) {
		fail("Can't write gid_map");
		exit(1);
	}

	futex_set_and_wake(&sh->fstate, TEST_MAPPED);
	futex_wait_while_lt(&sh->fstate, TEST_READY);

	/* Check we really have a nested user namespace before C/R */
	if (check_task_in_nested_userns(pid)) {
		fail("No nested user namespace before C/R");
		exit(1);
	}

	/* Stash our user namespace link to compare with the child's one */
	if (readlink("/proc/self/ns/user", sh->parent_ns_before, sizeof(sh->parent_ns_before) - 1) < 0) {
		fail("Can't readlink /proc/self/ns/user");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	/*
	 * The child has stashed the link of its user namespace, as
	 * reading the ns files of another task of a task in a nested
	 * user namespace may be restricted. Check that it is not
	 * ours, i.e. that the child is still in a nested one.
	 */
	if (!strcmp(sh->child_ns_after, sh->parent_ns_before)) {
		fail("The child is in our user namespace after C/R");
		ret = 1;
	}

	/*
	 * Give the child some time to check its state after C/R
	 * and exit, and then collect it. Its exit code tells whether
	 * the checks passed.
	 */
	futex_set_and_wake(&sh->fstate, TEST_CHECK);

	{
		int w;

		while ((w = wait(&status)) > 0) {
			if (w == pid) {
				if (!WIFEXITED(status) || WEXITSTATUS(status)) {
					pr_err("The child exited with status %d (%s%d)\n", status,
					       WIFSIGNALED(status) ? "signal " : "code ",
					       WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status));
					ret = 1;
				}
				break;
			}
		}
	}

	if (ret)
		return 1;

	if (sh->child_ret) {
		fail("Nested user namespace child failed");
		return 1;
	}

	pass();
	return 0;
}
