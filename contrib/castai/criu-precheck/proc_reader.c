#include "proc_reader.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Parse /proc/PID/stat for process state */
int parse_process_state(int pid, struct process_state *state)
{
	char path[PATH_MAX];
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_err("Failed to open %s: %s", path, strerror(errno));
		return -1;
	}

	if (getline(&line, &len, f) <= 0)
		goto out;

	/* Parse stat fields - careful with comm which can contain spaces */
	char *comm_start = strchr(line, '(');
	char *comm_end = strrchr(line, ')');
	if (!comm_start || !comm_end)
		goto out;

	/* Extract comm */
	size_t comm_len = comm_end - comm_start - 1;
	if (comm_len >= sizeof(state->comm))
		comm_len = sizeof(state->comm) - 1;
	memcpy(state->comm, comm_start + 1, comm_len);
	state->comm[comm_len] = '\0';

	/* Parse remaining fields after comm */
	int fields = sscanf(comm_end + 2,
			    "%c %d %d %d",
			    &state->state,
			    &state->ppid,
			    &state->pgid,
			    &state->sid);

	if (fields != 4)
		goto out;

	state->pid = pid;
	state->is_zombie = (state->state == 'Z');
	state->is_stopped = (state->state == 'T');
	state->is_session_leader = (state->pid == state->sid);

	/* Get thread count from /proc/PID/status */
	state->num_threads = get_thread_count(pid);

	ret = 0;

out:
	free(line);
	fclose(f);
	return ret;
}

/* Parse /proc/PID/smaps for VMA information */
int parse_vma_list(int pid, struct vma_info **vmas, unsigned long *total_private_kb)
{
	char path[PATH_MAX];
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	struct vma_info *current = NULL;
	unsigned long private_total = 0;

	*vmas = NULL;
	*total_private_kb = 0;

	snprintf(path, sizeof(path), "/proc/%d/smaps", pid);
	f = fopen(path, "r");
	if (!f) {
		pr_err("Failed to open %s: %s", path, strerror(errno));
		return -1;
	}

	while ((read = getline(&line, &len, f)) != -1) {
		/* New VMA line: "address-address perms offset dev:inode pathname" */
		if (sscanf(line, "%lx-%lx", &(unsigned long){0}, &(unsigned long){0}) == 2) {
			struct vma_info *vma = calloc(1, sizeof(*vma));
			if (!vma)
				break;

			char perms[5] = {0};
			unsigned long offset, dev_major, dev_minor;
			ino_t inode;

			sscanf(line, "%lx-%lx %4s %lx %lx:%lx %llu %[^\n]",
			       &vma->start, &vma->end, perms,
			       &offset, &dev_major, &dev_minor, (unsigned long long *)&inode,
			       vma->pathname);

			vma->size = vma->end - vma->start;

			/* Parse permissions */
			vma->prot = 0;
			if (perms[0] == 'r') vma->prot |= 0x1; /* PROT_READ */
			if (perms[1] == 'w') vma->prot |= 0x2; /* PROT_WRITE */
			if (perms[2] == 'x') vma->prot |= 0x4; /* PROT_EXEC */

			/* Parse flags */
			vma->flags = (perms[3] == 'p') ? 0x02 : 0x01; /* MAP_PRIVATE : MAP_SHARED */

			/* Detect VMA type */
			if (strstr(vma->pathname, "anon_inode:[aio]"))
				vma->type = VMA_AIORING;
			else if (strstr(vma->pathname, "SYSV"))
				vma->type = VMA_SYSVIPC;
			else if (strstr(vma->pathname, "socket:"))
				vma->type = VMA_SOCKET;
			else
				vma->type = VMA_REGULAR;

			/* Detect special VMAs */
			if (strcmp(vma->pathname, "[vdso]") == 0)
				vma->is_vdso = true;

			if (vma->prot & 0x4) /* PROT_EXEC */
				vma->is_executable = true;

			/* Add to list */
			vma->next = *vmas;
			*vmas = vma;
			current = vma;
		}
		/* Parse VMA details */
		else if (current) {
			if (sscanf(line, "Private_Clean: %lu", &current->private_kb) == 1 ||
			    sscanf(line, "Private_Dirty: %lu", &(unsigned long){0}) == 1) {
				unsigned long val;
				if (sscanf(line, "Private_Dirty: %lu", &val) == 1) {
					current->private_kb += val;
					private_total += val;
				}
			}
			if (sscanf(line, "Shared_Clean: %lu", &current->shared_kb) == 1 ||
			    sscanf(line, "Shared_Dirty: %lu", &(unsigned long){0}) == 1) {
				unsigned long val;
				if (sscanf(line, "Shared_Dirty: %lu", &val) == 1) {
					current->shared_kb += val;
				}
			}
		}
	}

	*total_private_kb = private_total;

	free(line);
	fclose(f);
	return 0;
}

/* Parse /proc/PID/fd/ for file descriptors */
int parse_fd_list(int pid, struct fd_info **fds)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;

	*fds = NULL;

	snprintf(path, sizeof(path), "/proc/%d/fd", pid);
	dir = opendir(path);
	if (!dir) {
		pr_err("Failed to open %s: %s", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		int fd_num;
		if (safe_atoi(entry->d_name, &fd_num) < 0)
			continue;

		struct fd_info *fd = calloc(1, sizeof(*fd));
		if (!fd)
			break;

		fd->fd_num = fd_num;

		/* Read symlink target */
		char link_path[PATH_MAX];
		snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", pid, fd_num);

		ssize_t len = readlink(link_path, fd->target, sizeof(fd->target) - 1);
		if (len > 0) {
			fd->target[len] = '\0';

			/* Detect FD types */
			if (strstr(fd->target, "socket:")) {
				fd->is_socket = true;
				/* Extract inode */
				if (sscanf(fd->target, "socket:[%llu]", (unsigned long long *)&fd->socket_inode) == 1) {
					/* Success */
				}
				strncpy(fd->type, "sock", sizeof(fd->type) - 1);
			} else if (strcmp(fd->target, "anon_inode:[io_uring]") == 0) {
				fd->is_io_uring = true;
				strncpy(fd->type, "io_uring", sizeof(fd->type) - 1);
			} else if (strcmp(fd->target, "anon_inode:[eventpoll]") == 0) {
				fd->is_epoll = true;
				strncpy(fd->type, "epoll", sizeof(fd->type) - 1);
			} else if (strcmp(fd->target, "anon_inode:[eventfd]") == 0) {
				fd->is_eventfd = true;
				strncpy(fd->type, "eventfd", sizeof(fd->type) - 1);
			} else if (strcmp(fd->target, "anon_inode:[signalfd]") == 0) {
				fd->is_signalfd = true;
				strncpy(fd->type, "signalfd", sizeof(fd->type) - 1);
			} else if (strcmp(fd->target, "anon_inode:[timerfd]") == 0) {
				fd->is_timerfd = true;
				strncpy(fd->type, "timerfd", sizeof(fd->type) - 1);
			} else if (strstr(fd->target, "anon_inode:[pidfd]")) {
				fd->is_pidfd = true;
				strncpy(fd->type, "pidfd", sizeof(fd->type) - 1);
			} else if (fd->target[0] == '/') {
				if (strncmp(fd->target, "/dev/", 5) == 0) {
					fd->is_device = true;
					strncpy(fd->type, "dev", sizeof(fd->type) - 1);
				} else {
					strncpy(fd->type, "reg", sizeof(fd->type) - 1);
				}
			} else if (strncmp(fd->target, "pipe:", 5) == 0) {
				strncpy(fd->type, "pipe", sizeof(fd->type) - 1);
			} else {
				strncpy(fd->type, "unknown", sizeof(fd->type) - 1);
			}
		}

		/* Add to list */
		fd->next = *fds;
		*fds = fd;
	}

	closedir(dir);
	return 0;
}

/* Parse /proc/PID/ns/ * for namespace information */
int parse_namespaces(int pid, struct namespace_info *nsinfo)
{
	char path[PATH_MAX];
	struct stat st;
	const char *ns_types[] = {"mnt", "net", "ipc", "uts", "pid", "user", "cgroup", "time"};
	ino_t init_ns[8] = {0};
	ino_t proc_ns[8] = {0};

	/* Read init (PID 1) namespace IDs */
	for (int i = 0; i < 8; i++) {
		snprintf(path, sizeof(path), "/proc/1/ns/%s", ns_types[i]);
		if (stat(path, &st) == 0)
			init_ns[i] = st.st_ino;
	}

	/* Read process namespace IDs */
	for (int i = 0; i < 8; i++) {
		snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, ns_types[i]);
		if (stat(path, &st) == 0)
			proc_ns[i] = st.st_ino;
	}

	/* Fill in namespace info */
	nsinfo->mnt_ns = proc_ns[0];
	nsinfo->net_ns = proc_ns[1];
	nsinfo->ipc_ns = proc_ns[2];
	nsinfo->uts_ns = proc_ns[3];
	nsinfo->pid_ns = proc_ns[4];
	nsinfo->user_ns = proc_ns[5];
	nsinfo->cgroup_ns = proc_ns[6];
	nsinfo->time_ns = proc_ns[7];

	/* Detect isolation */
	nsinfo->mnt_isolated = (proc_ns[0] != 0 && proc_ns[0] != init_ns[0]);
	nsinfo->net_isolated = (proc_ns[1] != 0 && proc_ns[1] != init_ns[1]);
	nsinfo->ipc_isolated = (proc_ns[2] != 0 && proc_ns[2] != init_ns[2]);
	nsinfo->uts_isolated = (proc_ns[3] != 0 && proc_ns[3] != init_ns[3]);
	nsinfo->pid_isolated = (proc_ns[4] != 0 && proc_ns[4] != init_ns[4]);
	nsinfo->user_isolated = (proc_ns[5] != 0 && proc_ns[5] != init_ns[5]);
	nsinfo->cgroup_isolated = (proc_ns[6] != 0 && proc_ns[6] != init_ns[6]);
	nsinfo->time_isolated = (proc_ns[7] != 0 && proc_ns[7] != init_ns[7]);

	return 0;
}

/* Get thread count */
int get_thread_count(int pid)
{
	char path[PATH_MAX];
	DIR *dir;
	int count = 0;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (!dir)
		return 1; /* Assume single-threaded on error */

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] != '.')
			count++;
	}

	closedir(dir);
	return count;
}

/* Get executable path */
char *get_exe_path(int pid)
{
	char path[PATH_MAX];
	char *exe = malloc(PATH_MAX);
	if (!exe)
		return NULL;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ssize_t len = readlink(path, exe, PATH_MAX - 1);
	if (len < 0) {
		free(exe);
		return NULL;
	}

	exe[len] = '\0';
	return exe;
}

/* Get current working directory */
char *get_cwd_path(int pid)
{
	char path[PATH_MAX];
	char *cwd = malloc(PATH_MAX);
	if (!cwd)
		return NULL;

	snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
	ssize_t len = readlink(path, cwd, PATH_MAX - 1);
	if (len < 0) {
		free(cwd);
		return NULL;
	}

	cwd[len] = '\0';
	return cwd;
}

/* Get root directory */
char *get_root_path(int pid)
{
	char path[PATH_MAX];
	char *root = malloc(PATH_MAX);
	if (!root)
		return NULL;

	snprintf(path, sizeof(path), "/proc/%d/root", pid);
	ssize_t len = readlink(path, root, PATH_MAX - 1);
	if (len < 0) {
		free(root);
		return NULL;
	}

	root[len] = '\0';
	return root;
}

/* Cleanup functions */
void free_vma_list(struct vma_info *head)
{
	while (head) {
		struct vma_info *next = head->next;
		free(head);
		head = next;
	}
}

void free_fd_list(struct fd_info *head)
{
	while (head) {
		struct fd_info *next = head->next;
		free(head);
		head = next;
	}
}

void free_mount_list(struct mount_info *head)
{
	while (head) {
		struct mount_info *next = head->next;
		free(head);
		head = next;
	}
}

void free_timer_list(struct timer_info *head)
{
	while (head) {
		struct timer_info *next = head->next;
		free(head);
		head = next;
	}
}

void free_cgroup_list(struct cgroup_info *head)
{
	while (head) {
		struct cgroup_info *next = head->next;
		free(head);
		head = next;
	}
}

/* Parse /proc/PID/mountinfo for mount information */
int parse_mounts(int pid, struct mount_info **mounts)
{
	char path[PATH_MAX];
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	*mounts = NULL;

	snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		struct mount_info *mount = calloc(1, sizeof(*mount));
		if (!mount)
			break;

		/* Parse mountinfo format:
		 * mnt_id parent_id major:minor root mount_point options - fs_type source super_options
		 */
		int fields = sscanf(line, "%d %d %s %s %s %s",
				    &mount->mnt_id,
				    &mount->parent_id,
				    mount->dev,
				    mount->root,
				    mount->mount_point,
				    mount->options);

		if (fields < 6) {
			free(mount);
			continue;
		}

		/* Find the separator " - " to get fs_type */
		char *sep = strstr(line, " - ");
		if (sep) {
			sep += 3; /* Skip " - " */
			sscanf(sep, "%s", mount->fs_type);
		}

		/* Detect bind mounts */
		mount->is_bind = (strcmp(mount->root, "/") != 0);

		/* Detect shared mounts */
		mount->is_shared = (strstr(mount->options, "shared:") != NULL);

		/* Detect external filesystems */
		mount->is_external = (strcmp(mount->fs_type, "nfs") == 0 ||
				      strcmp(mount->fs_type, "cifs") == 0 ||
				      strcmp(mount->fs_type, "fuse") == 0 ||
				      strcmp(mount->fs_type, "9p") == 0);

		/* Add to list */
		mount->next = *mounts;
		*mounts = mount;
	}

	free(line);
	fclose(f);
	return 0;
}

int parse_timers(int pid, struct timer_info **timers)
{
	(void)pid;
	*timers = NULL;
	/* TODO: Implement /proc/PID/timers parsing */
	return 0;
}

int parse_cgroups(int pid, struct cgroup_info **cgroups)
{
	(void)pid;
	*cgroups = NULL;
	/* TODO: Implement /proc/PID/cgroup parsing */
	return 0;
}
