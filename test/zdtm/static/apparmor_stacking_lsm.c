#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Check AppArmor profile restore on kernels with stacked LSMs. "
			  "On such kernels the generic /proc/self/attr/current is owned "
			  "by the display LSM and rejects AppArmor commands with EINVAL. "
			  "CRIU must fall back to /proc/self/attr/apparmor/current.";
const char *test_author	= "CastAI <dev@cast.ai>";

#define PROFILE "criu_test"

/*
 * Read the current AppArmor profile name.  AppArmor exposes the value as
 * "<name> (enforce)" or "<name> (complain)"; we return only the bare name.
 *
 * Returns 0 on success and fills buf, -1 on error.
 */
static int read_apparmor_profile(char *buf, size_t bufsz)
{
	char fmt[32];
	FILE *f;
	int ret;

	/*
	 * Prefer the LSM-specific path; fall back to the generic one on
	 * kernels without per-LSM attr directories (pre-5.1).
	 */
	f = fopen("/proc/self/attr/apparmor/current", "r");
	if (!f)
		f = fopen("/proc/self/attr/current", "r");
	if (!f) {
		pr_perror("Can't open AppArmor attr file");
		return -1;
	}

	/* Read only the bare profile name, stopping at space or newline. */
	snprintf(fmt, sizeof(fmt), "%%%zu[^ \n]", bufsz - 1);
	ret = fscanf(f, fmt, buf);
	fclose(f);

	if (ret != 1) {
		fail("Could not parse AppArmor profile");
		return -1;
	}

	return 0;
}

/*
 * Apply an AppArmor profile via the LSM-specific attr path.
 * Falls back to the generic path on kernels without per-LSM attr directories.
 */
static int set_apparmor_profile(const char *profile)
{
	char cmd[256];
	int fd, len, ret;

	len = snprintf(cmd, sizeof(cmd), "changeprofile %s", profile);
	if (len < 0 || len >= (int)sizeof(cmd)) {
		fail("profile name too long");
		return -1;
	}

	/*
	 * Try the LSM-specific path first to mirror what CRIU does on restore.
	 * Fall back to the generic path for older kernels.
	 */
	fd = open("/proc/self/attr/apparmor/current", O_WRONLY);
	if (fd < 0)
		fd = open("/proc/self/attr/current", O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open AppArmor attr file for writing");
		return -1;
	}

	ret = write(fd, cmd, len);
	close(fd);

	if (ret < 0) {
		pr_perror("Can't write AppArmor profile");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char profile_before[256];
	char profile_after[256];

	test_init(argc, argv);

	/* Apply the test profile before checkpoint. */
	if (set_apparmor_profile(PROFILE) < 0)
		return 1;

	if (read_apparmor_profile(profile_before, sizeof(profile_before)) < 0)
		return 1;

	if (strcmp(profile_before, PROFILE) != 0) {
		fail("profile not set before C/R: got '%s', want '%s'",
		     profile_before, PROFILE);
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* After restore, the profile must still be the one we set. */
	if (read_apparmor_profile(profile_after, sizeof(profile_after)) < 0)
		return 1;

	if (strcmp(profile_after, PROFILE) != 0) {
		fail("profile changed after C/R: got '%s', want '%s'",
		     profile_after, PROFILE);
		return 1;
	}

	pass();
	return 0;
}
