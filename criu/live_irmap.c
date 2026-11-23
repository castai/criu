/*
 * Live-migration irmap scan-root coverage.
 *
 * A file with st_dev == dev can only live at or under a mount of that
 * device, so a scan root can reach the watch only when the mount the
 * root itself sits in is of that device (the walk stays inside it), or
 * when a mount of the device hangs below the root (the walk descends
 * into it). Path chains are cut at mount boundaries, so a root under
 * the NFS mount cannot reach overlay files, however the mount tree
 * looks. Roots that cover nothing are skipped before any walk.
 *
 * ns_mountpoint values are relative to the mount namespace root and
 * carry a "./" prefix ("." alone for the root mount), while scan roots
 * are absolute: normalize before comparing, or every containment test
 * fails and the root mount ends up covering everything.
 *
 * This file is included directly into irmap.c.
 */

static bool live_irmap_root_covers_dev(char *root, unsigned int dev)
{
	struct mount_info *m, *containing = NULL;
	bool known = false;
	char root_buf[PATH_MAX];
	char *root_norm;
	size_t containing_len = 0;

	root_norm = root;
	if (root[0] != '/') {
		snprintf(root_buf, sizeof(root_buf), "/%s", root);
		root_norm = root_buf;
	}

#define nsmp(m) (!strcmp((m)->ns_mountpoint, ".") ? "/" : \
		 strncmp((m)->ns_mountpoint, "./", 2) ? (m)->ns_mountpoint : (m)->ns_mountpoint + 1)

	for (m = mntinfo; m; m = m->next) {
		if (m->s_dev != dev)
			continue;
		known = true;
		if (is_sub_path(nsmp(m), root_norm))
			return true;
	}

	for (m = mntinfo; m; m = m->next) {
		char *mnp = nsmp(m);
		size_t len = strlen(mnp);

		if (!is_sub_path(root_norm, mnp))
			continue;
		/* Ties are impossible: mountpoints are unique. */
		if (!containing || len >= containing_len) {
			containing = m;
			containing_len = len;
		}
	}

#undef nsmp

	if (containing && containing->s_dev == dev)
		return true;

	/* Device missing from the mount table keeps the blind behavior. */
	return !known;
}
