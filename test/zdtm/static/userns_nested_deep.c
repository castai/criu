#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <grp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "A user namespace nested two levels below the root task is refused by the dump";
const char *test_author = "CAST AI";

/*
 * The --nested-ns support translates the id maps through one level
 * only: a user namespace created by a task of a nested one (C below B
 * below the root task A) must be refused at dump with a clear error,
 * not restored with wrong maps. The test is expected to fail its C/R
 * (crfail): the dump has to fail, and the tree has to survive it.
 */

struct id_extent {
	unsigned int first;
	unsigned int lower_first;
	unsigned int count;
};

enum {
	ST_INIT,
	B_UNSHARED,
	B_MAPPED,
	C_UNSHARED,
	C_MAPPED,
	ST_READY,
	ST_DONE,
};

struct shared {
	futex_t state;
	struct id_extent uid_ext;
	struct id_extent gid_ext;
	int c_ret;
};

static struct shared *sh;

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

static int pick_extent(const char *path, struct id_extent *ext)
{
	char buf[4096];
	char *line, *save;
	int nr = 0;

	if (read_file_text(path, buf, sizeof(buf)))
		return -1;

	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		unsigned int first, lower_first, count;

		if (sscanf(line, "%u %u %u", &first, &lower_first, &count) != 3) {
			pr_err("Bad map line '%s' in %s\n", line, path);
			return -1;
		}

		if (!nr || first) {
			ext->first = first;
			ext->lower_first = lower_first;
			ext->count = count;
		}
		nr++;
		if (first)
			break;
	}

	if (!nr) {
		pr_err("No extents in %s\n", path);
		return -1;
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

/* C: the user namespace two levels below the root task */
static int task_c(void)
{
	if (unshare(CLONE_NEWUSER)) {
		pr_perror("Can't unshare the user namespace of C");
		return -1;
	}

	futex_set_and_wake(&sh->state, C_UNSHARED);
	futex_wait_until(&sh->state, C_MAPPED);

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids in C: uid=%d gid=%d\n", getuid(), getgid());
		return -1;
	}

	futex_set_and_wake(&sh->state, ST_READY);
	futex_wait_until(&sh->state, ST_DONE);

	return 0;
}

/* B: the user namespace nested in the one of the root task, the creator of C's one */
static int task_b(void)
{
	pid_t c;
	int status;

	if (setgroups(0, NULL) && errno != EPERM) {
		pr_perror("Can't drop the groups");
		return -1;
	}
	if (setresgid(sh->gid_ext.first, sh->gid_ext.first, sh->gid_ext.first) ||
	    setresuid(sh->uid_ext.first, sh->uid_ext.first, sh->uid_ext.first)) {
		pr_perror("Can't switch to the sub-ids");
		return -1;
	}
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) {
		pr_perror("Can't set the dumpable flag");
		return -1;
	}
	if (unshare(CLONE_NEWUSER)) {
		pr_perror("Can't unshare the user namespace of B");
		return -1;
	}

	futex_set_and_wake(&sh->state, B_UNSHARED);
	futex_wait_until(&sh->state, B_MAPPED);

	if (getuid() != 0 || getgid() != 0) {
		pr_err("Unexpected ids in B: uid=%d gid=%d\n", getuid(), getgid());
		return -1;
	}

	c = fork();
	if (c < 0) {
		pr_perror("Can't fork C");
		return -1;
	}
	if (c == 0)
		exit(task_c() ? 1 : 0);

	futex_wait_until(&sh->state, C_UNSHARED);

	/* Our own root id is the only one we can map into C */
	if (write_map_file(c, "setgroups", "deny") || write_map_file(c, "uid_map", "0 0 1\n") ||
	    write_map_file(c, "gid_map", "0 0 1\n")) {
		kill(c, SIGKILL);
		waitpid(c, NULL, 0);
		return -1;
	}

	futex_set_and_wake(&sh->state, C_MAPPED);

	while (waitpid(c, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("C exited with status %d\n", status);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char buf[256];
	pid_t b;
	int status;

	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("Can't map the shared region");
		exit(1);
	}
	futex_set(&sh->state, ST_INIT);

	test_init(argc, argv);

	if (pick_extent("/proc/self/uid_map", &sh->uid_ext) || pick_extent("/proc/self/gid_map", &sh->gid_ext)) {
		fail("Can't pick the id extents");
		exit(1);
	}

	b = fork();
	if (b < 0) {
		pr_perror("Can't fork B");
		exit(1);
	}
	if (b == 0)
		exit(task_b() ? 1 : 0);

	futex_wait_until(&sh->state, B_UNSHARED);

	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->uid_ext.first, sh->uid_ext.count);
	if (write_map_file(b, "setgroups", "deny") || write_map_file(b, "uid_map", buf)) {
		fail("Can't write the uid map of B");
		exit(1);
	}
	snprintf(buf, sizeof(buf), "0 %u %u\n", sh->gid_ext.first, sh->gid_ext.count);
	if (write_map_file(b, "gid_map", buf)) {
		fail("Can't write the gid map of B");
		exit(1);
	}

	futex_set_and_wake(&sh->state, B_MAPPED);
	futex_wait_until(&sh->state, ST_READY);

	test_daemon();
	test_waitsig();

	futex_set_and_wake(&sh->state, ST_DONE);

	while (waitpid(b, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("B exited with status %d", status);
		exit(1);
	}

	pass();
	return 0;
}
