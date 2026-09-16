static int write_child_id_maps(struct uns_id_maps *maps, int dfd)
{
	if (write_id_map_extents(dfd, maps->target, maps->extents, maps->n_uid_map, "uid_map"))
		return -1;

	if (write_id_map_extents(dfd, maps->target, maps->extents + maps->n_uid_map, maps->n_gid_map, "gid_map"))
		return -1;

	return 0;
}

static int write_id_map_path(pid_t pid, const char *id_map, UidGidExtent *extents, int n)
{
	char buf[PAGE_SIZE];
	char path[64];
	int off = 0, fd, i;

	/*
	 * We can perform only a single write (that may contain multiple
	 * newline-delimited records) to a uid_map and a gid_map file.
	 */
	for (i = 0; i < n; i++) {
		int len;

		len = snprintf(buf + off, sizeof(buf) - off, "%u %u %u\n", extents[i].first, extents[i].lower_first,
			       extents[i].count);
		if (len < 0 || len >= sizeof(buf) - off) {
			pr_err("The user/group mappings buffer truncated\n");
			return -1;
		}
		off += len;
	}

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, id_map);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	if (write(fd, buf, off) != off) {
		pr_perror("Unable to write into %s", id_map);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/*
 * Find the pid of the task @vpid in the pid namespace of criu, using
 * its NSpid line. The passed @fd is a /proc of the restored tree, in
 * which the task is visible by its virtual pid.
 */
static pid_t lookup_global_pid(int fd, pid_t vpid)
{
	char status[4096];
	char spath[32];
	int sfd, sn;
	pid_t global_pid = 0;

	snprintf(spath, sizeof(spath), "%d/status", vpid);
	sfd = openat(fd, spath, O_RDONLY);
	sn = sfd >= 0 ? read(sfd, status, sizeof(status) - 1) : -1;
	if (sfd >= 0)
		close(sfd);

	if (sn > 0) {
		char *line, *save;

		status[sn] = 0;
		line = strtok_r(status, "\n", &save);
		while (line) {
			if (!strncmp(line, "NSpid:", 6)) {
				int v;

				/* the first number is the one in our pid namespace */
				if (sscanf(line + 6, "%d", &v) == 1)
					global_pid = v;
				break;
			}
			line = strtok_r(NULL, "\n", &save);
		}
	}

	return global_pid;
}

/*
 * The writer of the uid_map and gid_map files has to be in the
 * parent user namespace of the one being filled in (see
 * proc_uid_map_write() in the kernel). Besides, it has to have
 * capabilities over that user namespace, and the restored tasks
 * have none, as their credentials are changed after entering
 * the user namespace.
 *
 * So fork a worker which enters the user namespace of the calling
 * task (the parent user namespace of the new one) and writes the
 * maps there. Runs in the usernsd context, as the daemon keeps
 * the capabilities of the criu process. The worker looks the
 * target up by its pid in the pid namespace of criu, as writing
 * through the /proc of the restored tree does not work from
 * another user namespace for some reason.
 */
static int uns_write_id_maps(void *arg, int fd, pid_t pid)
{
	struct uns_id_maps *maps = arg;
	int status, worker;

	/*
	 * Called directly: we are the task that has forked the child,
	 * so we are already in the parent user namespace of the new
	 * one and can write the maps ourselves.
	 */
	if (pid == getpid())
		return write_child_id_maps(maps, fd);

	worker = fork();
	if (worker < 0) {
		pr_perror("Can't fork a userns maps writer");
		return -1;
	}

	if (worker == 0) {
		pid_t target;

		if (switch_ns(pid, &user_ns_desc, NULL))
			_exit(1);

		target = lookup_global_pid(fd, maps->target);
		if (target <= 0) {
			pr_err("Can't find the pid of the task %d\n", maps->target);
			_exit(1);
		}

		if (write_id_map_path(target, "uid_map", maps->extents, maps->n_uid_map))
			_exit(1);

		if (write_id_map_path(target, "gid_map", maps->extents + maps->n_uid_map, maps->n_gid_map))
			_exit(1);

		_exit(0);
	}

	if (waitpid(worker, &status, 0) != worker) {
		pr_perror("Can't wait the userns maps writer");
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("Writing the userns maps failed with %d\n", status);
		return -1;
	}

	return 0;
}
