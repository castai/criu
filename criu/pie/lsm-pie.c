/*
 * AppArmor label restore helper for the PIE restorer stub.
 *
 * This file is included directly into restorer.c to keep it in the same
 * translation unit (required for PIE code that cannot use shared libraries).
 *
 * On kernels with CONFIG_SECURITY_STACKING, the generic
 * /proc/<pid>/attr/current is owned by the display LSM. When AppArmor is
 * not the display LSM, writing an AppArmor changeprofile command to the
 * generic path returns EINVAL. Linux 5.1+ provides per-LSM attr directories
 * under /proc/<pid>/attr/<lsmname>/; this helper writes there instead.
 *
 * Called from restore_creds() and __export_restore_task() in place of
 * lsm_set_label() when lsm_type == LSMTYPE__APPARMOR.
 */
static int castai_apparmor_set_label(char *label, char *type, int procfd)
{
	int ret, len, lsmfd;
	char path[STD_LOG_SIMPLE_CHUNK];

	if (!label)
		return 0;

	for (len = 0; label[len]; len++)
		;

	/*
	 * Try the per-LSM AppArmor attr path first. If the kernel does not
	 * provide per-LSM attr directories (pre-5.1), fall back to the generic
	 * per-thread path used by lsm_set_label().
	 */
	std_sprintf(path, "self/attr/apparmor/%s", type);
	lsmfd = sys_openat(procfd, path, O_WRONLY, 0);
	if (lsmfd < 0) {
		std_sprintf(path, "self/task/%ld/attr/%s", sys_gettid(), type);
		lsmfd = sys_openat(procfd, path, O_WRONLY, 0);
	}
	if (lsmfd < 0) {
		/*
		 * Neither attr path is accessible. Fall through to the
		 * soft-fail path below so the restore is not aborted.
		 */
		pr_warn("castai: can't open AppArmor attr path, skipping\n");
		return 0;
	}

	ret = sys_write(lsmfd, label, len);
	sys_close(lsmfd);

	if (ret == -EACCES) {
		/*
		 * The OCI runtime applies the container's AppArmor profile
		 * before invoking criu restore. The restored process therefore
		 * already runs under the target profile when the restorer stub
		 * executes. AppArmor returns EACCES for a changeprofile
		 * transition when the active profile has no explicit
		 * change_profile rule, even if the target profile is identical
		 * to the current one.
		 *
		 * Read the current profile and treat the write as a no-op if
		 * the process is already confined to the requested name.
		 */
		const char *want = label;
		char cur[STD_LOG_SIMPLE_CHUNK];
		int curfd, curlen, wantlen;

		/*
		 * The label is in AppArmor changeprofile syntax:
		 * "changeprofile <name>". Strip the verb to get the bare
		 * profile name for comparison.
		 */
		if (!std_strncmp(want, "changeprofile ", 14))
			want += 14;
		for (wantlen = 0; want[wantlen]; wantlen++)
			;

		/* Read back what profile is actually active now. */
		curfd = sys_openat(procfd, "self/attr/apparmor/current",
				   O_RDONLY, 0);
		if (curfd >= 0) {
			curlen = sys_read(curfd, cur, sizeof(cur) - 1);
			sys_close(curfd);
			if (curlen > 0)
				cur[curlen] = '\0';
			else
				cur[0] = '\0';
			/*
			 * AppArmor exposes the active profile as
			 * "<name> (enforce)" or "<name> (complain)".
			 * Match only the bare name prefix so the mode
			 * suffix does not affect the comparison.
			 */
			if (curlen >= wantlen &&
			    !std_strncmp(cur, want, wantlen) &&
			    (cur[wantlen] == '\0' || cur[wantlen] == ' ' ||
			     cur[wantlen] == '\n')) {
				/*
				 * Profile already set -- write was a no-op.
				 */
				cur[wantlen] = '\0';
				pr_info("castai: AppArmor profile %s already active\n", cur);
				ret = len;
			} else {
				/*
				 * Genuine permission error: a different profile
				 * is active and we cannot change it.
				 */
				pr_err("castai: EACCES writing AppArmor profile: want=%s have=%s\n",
				       want, cur);
			}
		} else {
			/*
			 * Cannot determine the current profile; treat as error.
			 */
			pr_err("castai: EACCES writing AppArmor profile, "
			       "attr/apparmor/current unreadable\n");
		}
	}

	if (ret < 0) {
		/*
		 * All write attempts failed. The OCI runtime is responsible
		 * for applying the container profile via the runtime spec;
		 * the restorer stub is a best-effort path. Aborting the
		 * restore here would leave the process tree in a half-restored
		 * state, which is worse than continuing without the profile
		 * transition. Emit a warning and let the restore proceed.
		 */
		pr_warn("castai: could not write AppArmor profile %s (ret=%d); continuing\n",
			label, ret);
		return 0;
	}

	return 0;
}
