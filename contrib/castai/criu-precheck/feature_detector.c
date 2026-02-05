#include "feature_detector.h"
#include <sys/utsname.h>
#include <fcntl.h>

#define PAGE_SIZE 4096

/* Detect io_uring usage */
int detect_io_uring(struct fd_info *fds, struct vma_info *vmas,
		    struct feature_results *results, struct issue **issues)
{
	int count = 0;

	/* Check file descriptors */
	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		if (fd->is_io_uring) {
			count++;

			char affected[128];
			snprintf(affected, sizeof(affected), "fd:%d", fd->fd_num);

			struct issue *issue = issue_new(
				ISSUE_IO_URING_DETECTED,
				SEVERITY_CRITICAL,
				"io_uring detected - CRIU checkpoint will likely fail",
				"Close io_uring before checkpoint, or skip this process. "
				"io_uring state cannot be fully captured by CRIU.",
				affected
			);
			issue_add(issues, issue);
		}
	}

	/* Check VMAs for AIO rings */
	for (struct vma_info *vma = vmas; vma; vma = vma->next) {
		if (vma->type == VMA_AIORING)
			count++;
	}

	results->io_uring_detected = (count > 0);
	results->io_uring_count = count;

	return 0;
}

/* Detect RSEQ usage and kernel support */
int detect_rseq_usage(int pid, struct vma_info *vmas,
		      struct feature_results *results, struct issue **issues)
{
	bool rseq_likely = false;

	/* Check if glibc 2.35+ is mapped (uses RSEQ by default) */
	char *exe = get_exe_path(pid);
	if (exe) {
		/* Check if process uses modern glibc */
		for (struct vma_info *vma = vmas; vma; vma = vma->next) {
			if (strstr(vma->pathname, "libc-") ||
			    strstr(vma->pathname, "libc.so")) {
				/* Modern glibc likely uses RSEQ */
				rseq_likely = true;
				break;
			}
			if (strstr(vma->pathname, "librseq")) {
				rseq_likely = true;
				break;
			}
		}
		free(exe);
	}

	if (rseq_likely) {
		/* Check kernel support */
		if (!results->kfeatures.has_rseq ||
		    !results->kfeatures.has_ptrace_get_rseq_conf) {

			struct issue *issue = issue_new(
				ISSUE_RSEQ_NO_KERNEL_SUPPORT,
				SEVERITY_CRITICAL,
				"Process likely uses RSEQ but kernel lacks "
				"PTRACE_GET_RSEQ_CONFIGURATION support",
				"Upgrade kernel to 5.13+ or use glibc < 2.35 to avoid RSEQ. "
				"CRIU dump will fail without ptrace rseq support.",
				"kernel"
			);
			issue_add(issues, issue);

			results->rseq_kernel_support_missing = true;
		} else {
			/* Just a warning */
			struct issue *issue = issue_new(
				ISSUE_RSEQ_LIKELY,
				SEVERITY_INFO,
				"Process likely uses RSEQ (modern glibc detected)",
				"Kernel has PTRACE_GET_RSEQ_CONFIGURATION support - should be OK",
				NULL
			);
			issue_add(issues, issue);
		}

		results->rseq_likely = true;
	}

	return 0;
}

/* Detect network features from /proc/PID/net */
int detect_network_features(int pid, struct fd_info *fds,
			     struct feature_results *results, struct issue **issues)
{
	int tcp_count = 0;
	char path[PATH_MAX];
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	/* Build a list of socket inodes from FDs */
	ino_t *socket_inodes = NULL;
	int socket_count = 0;

	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		if (fd->is_socket && fd->socket_inode) {
			socket_count++;
			socket_inodes = realloc(socket_inodes, socket_count * sizeof(ino_t));
			if (socket_inodes)
				socket_inodes[socket_count - 1] = fd->socket_inode;
		}
	}

	if (socket_count == 0)
		goto out;

	/* Check /proc/PID/net/tcp for ESTABLISHED connections */
	snprintf(path, sizeof(path), "/proc/%d/net/tcp", pid);
	f = fopen(path, "r");
	if (f) {
		/* Skip header */
		getline(&line, &len, f);

		while (getline(&line, &len, f) != -1) {
			unsigned long inode;
			char state[16];
			char local[64], remote[64];

			/* Parse line: sl local_address rem_address st tx_queue:rx_queue ... inode */
			if (sscanf(line, "%*d: %s %s %s %*s %*s %*s %*s %*s %*s %llu",
				   local, remote, state, (unsigned long long *)&inode) == 4) {

				/* Check if this socket belongs to our process */
				bool is_our_socket = false;
				for (int i = 0; i < socket_count; i++) {
					if (socket_inodes[i] == inode) {
						is_our_socket = true;
						break;
					}
				}

				if (is_our_socket && strcmp(state, "01") == 0) { /* 01 = ESTABLISHED */
					tcp_count++;
				}
			}
		}
		fclose(f);
	}

	/* Check /proc/PID/net/tcp6 as well */
	snprintf(path, sizeof(path), "/proc/%d/net/tcp6", pid);
	f = fopen(path, "r");
	if (f) {
		/* Skip header */
		free(line);
		line = NULL;
		len = 0;
		getline(&line, &len, f);

		while (getline(&line, &len, f) != -1) {
			unsigned long inode;
			char state[16];
			char local[64], remote[64];

			if (sscanf(line, "%*d: %s %s %s %*s %*s %*s %*s %*s %*s %llu",
				   local, remote, state, (unsigned long long *)&inode) == 4) {

				bool is_our_socket = false;
				for (int i = 0; i < socket_count; i++) {
					if (socket_inodes[i] == inode) {
						is_our_socket = true;
						break;
					}
				}

				if (is_our_socket && strcmp(state, "01") == 0) {
					tcp_count++;
				}
			}
		}
		fclose(f);
	}

	if (tcp_count > 0) {
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "%d active TCP ESTABLISHED connection(s) detected", tcp_count);

		struct issue *issue = issue_new(
			ISSUE_TCP_ESTABLISHED,
			SEVERITY_WARNING,
			desc,
			"Use --tcp-established flag with CRIU dump. "
			"Active TCP connections require kernel TCP_REPAIR support.",
			"network"
		);
		issue_add(issues, issue);

		results->tcp_established = true;
		results->tcp_established_count = tcp_count;
	}

out:
	free(socket_inodes);
	free(line);
	return 0;
}

/* Detect SysVIPC issues */
int detect_sysvipc_issues(struct vma_info *vmas, struct namespace_info *nsinfo,
			   struct feature_results *results, struct issue **issues)
{
	bool has_sysvipc = false;

	for (struct vma_info *vma = vmas; vma; vma = vma->next) {
		if (vma->type == VMA_SYSVIPC) {
			has_sysvipc = true;
			break;
		}
	}

	if (has_sysvipc && !nsinfo->ipc_isolated) {
		struct issue *issue = issue_new(
			ISSUE_SYSVIPC_NO_IPC_NS,
			SEVERITY_CRITICAL,
			"SysVIPC shared memory detected without IPC namespace isolation",
			"This is a guaranteed dump failure. Process must be in isolated IPC namespace "
			"to use SysVIPC shared memory. Restart process in IPC namespace.",
			"memory"
		);
		issue_add(issues, issue);

		results->sysvipc_without_ipc_ns = true;
	}

	return 0;
}

/* Check AIO ring alignment */
int check_aio_ring_alignment(struct vma_info *vmas,
			      struct feature_results *results, struct issue **issues)
{
	for (struct vma_info *vma = vmas; vma; vma = vma->next) {
		if (vma->type == VMA_AIORING) {
			if (vma->size % PAGE_SIZE != 0) {
				char desc[256];
				snprintf(desc, sizeof(desc),
					 "AIO ring at 0x%lx has non-page-aligned size: %lu bytes",
					 vma->start, vma->size);

				struct issue *issue = issue_new(
					ISSUE_AIO_RING_MISALIGNED,
					SEVERITY_CRITICAL,
					desc,
					"AIO ring size must be page-aligned. This will cause dump failure.",
					"memory"
				);
				issue_add(issues, issue);

				results->aio_ring_misaligned = true;
			}
		}
	}

	return 0;
}

/* Check kernel features */
int check_kernel_features(struct kernel_features *kfeatures)
{
	struct utsname uts;

	/* Initialize all to false */
	memset(kfeatures, 0, sizeof(*kfeatures));

	if (uname(&uts) < 0) {
		pr_warn("Failed to get kernel version");
		return -1;
	}

	/* Parse kernel version */
	int major, minor;
	if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
		pr_warn("Failed to parse kernel version: %s", uts.release);
		return -1;
	}

	pr_debug("Kernel version: %d.%d", major, minor);

	/* Feature availability based on kernel version */
	/* These are rough estimates - actual availability depends on config */

	kfeatures->has_kcmp = (major >= 3 && minor >= 5); /* 3.5+ */
	kfeatures->has_tcp_repair = (major >= 3 && minor >= 5); /* 3.5+ */

	kfeatures->has_memfd = (major >= 3 && minor >= 17); /* 3.17+ */
	kfeatures->has_uffd = (major >= 4 && minor >= 3); /* 4.3+ */
	kfeatures->has_userns = (major >= 3 && minor >= 8); /* 3.8+ */

	kfeatures->has_rseq = (major >= 4 && minor >= 18); /* 4.18+ */
	kfeatures->has_ptrace_get_rseq_conf = (major >= 5 && minor >= 13); /* 5.13+ */

	kfeatures->has_timens = (major >= 5 && minor >= 6); /* 5.6+ */
	kfeatures->has_clone3_set_tid = (major >= 5 && minor >= 5); /* 5.5+ */
	kfeatures->has_pidfd_open = (major >= 5 && minor >= 3); /* 5.3+ */

	kfeatures->has_timerfd = (major >= 2 && minor >= 6 && major > 2); /* 2.6.27+ */
	kfeatures->has_cgroupns = (major >= 4 && minor >= 6); /* 4.6+ */

	/* Check for actual feature availability by trying to access them */
	/* This is more accurate than version checking */

	/* Check RSEQ support */
	if (file_exists("/sys/kernel/rseq")) {
		kfeatures->has_rseq = true;
	}

	return 0;
}

/* Detect multithreading */
int detect_multithreading(int pid, struct feature_results *results,
			   struct issue **issues)
{
	int thread_count = get_thread_count(pid);

	results->multithreaded = (thread_count > 1);
	results->thread_count = thread_count;

	if (results->multithreaded) {
		char desc[256];
		snprintf(desc, sizeof(desc), "Process has %d threads", thread_count);

		struct issue *issue = issue_new(
			ISSUE_MULTITHREADED,
			SEVERITY_INFO,
			desc,
			"Multithreaded processes require ptrace for all threads. "
			"Ensure kernel supports ptrace of all threads.",
			NULL
		);
		issue_add(issues, issue);
	}

	return 0;
}

/* Detect MPTCP (Multipath TCP) usage */
int detect_mptcp(int pid, struct feature_results *results,
		 struct issue **issues)
{
	char path[PATH_MAX];
	int count = 0;

	/* Check if /proc/PID/net/mptcp exists */
	snprintf(path, sizeof(path), "/proc/%d/net/mptcp", pid);
	if (file_exists(path)) {
		FILE *f = fopen(path, "r");
		if (f) {
			char *line = NULL;
			size_t len = 0;

			/* Skip header */
			getline(&line, &len, f);

			/* Count MPTCP connections */
			while (getline(&line, &len, f) != -1) {
				count++;
			}

			free(line);
			fclose(f);

			if (count > 0) {
				char desc[256];
				snprintf(desc, sizeof(desc),
					 "MPTCP (Multipath TCP) detected - %d connection(s)",
					 count);

				struct issue *issue = issue_new(
					ISSUE_MPTCP_DETECTED,
					SEVERITY_CRITICAL,
					desc,
					"MPTCP is NOT supported by CRIU. Disable MPTCP before checkpoint. "
					"For Go programs: set GODEBUG=multipathtcp=0 environment variable. "
					"For system-wide: echo 0 > /proc/sys/net/mptcp/enabled",
					"network"
				);
				issue_add(issues, issue);

				results->mptcp_detected = true;
				results->mptcp_socket_count = count;
			}
		}
	}

	return 0;
}

/* Detect TTY/PTY usage */
int detect_tty(struct fd_info *fds, struct feature_results *results,
	       struct issue **issues)
{
	int count = 0;

	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		/* Check for /dev/pts/ *, /dev/tty *, /dev/console */
		if (strncmp(fd->target, "/dev/pts/", 9) == 0 ||
		    strncmp(fd->target, "/dev/tty", 8) == 0 ||
		    strcmp(fd->target, "/dev/console") == 0) {
			count++;
		}
	}

	if (count > 0) {
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "TTY/PTY device detected - %d terminal(s)",
			 count);

		struct issue *issue = issue_new(
			ISSUE_TTY_DETECTED,
			SEVERITY_WARNING,
			desc,
			"TTY handling requires special care. Use --shell-job flag if process "
			"is a shell job. Ensure controlling terminal is handled properly.",
			"tty"
		);
		issue_add(issues, issue);

		results->tty_detected = true;
		results->tty_count = count;
	}

	return 0;
}

/* Detect Seccomp filters */
int detect_seccomp(int pid, struct feature_results *results,
		   struct issue **issues)
{
	char path[PATH_MAX];
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	int seccomp_mode = 0;

	/* Read /proc/PID/status for Seccomp field */
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		if (sscanf(line, "Seccomp: %d", &seccomp_mode) == 1) {
			break;
		}
	}

	free(line);
	fclose(f);

	if (seccomp_mode > 0) {
		results->seccomp_enabled = true;

		/* Check if kernel supports PTRACE_O_SUSPEND_SECCOMP (kernel 4.7+) */
		struct utsname uts;
		if (uname(&uts) == 0) {
			int kmajor, kminor;
			if (sscanf(uts.release, "%d.%d", &kmajor, &kminor) == 2) {
				if (kmajor < 4 || (kmajor == 4 && kminor < 7)) {
					char desc[256];
					snprintf(desc, sizeof(desc),
						 "Seccomp filter active (mode %d) but kernel lacks PTRACE_O_SUSPEND_SECCOMP",
						 seccomp_mode);

					struct issue *issue = issue_new(
						ISSUE_SECCOMP_NO_KERNEL_SUPPORT,
						SEVERITY_CRITICAL,
						desc,
						"Upgrade kernel to 4.7+ for seccomp filter dumping support. "
						"Or disable seccomp before checkpoint.",
						"security"
					);
					issue_add(issues, issue);

					results->seccomp_kernel_support_missing = true;
					fclose(f);
					return 0;
				}
			}
		}

		/* Even with support, inform about seccomp */
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "Seccomp filter active (mode %d)",
			 seccomp_mode);

		struct issue *issue = issue_new(
			ISSUE_LSM_DETECTED, /* Reuse LSM for info */
			SEVERITY_INFO,
			desc,
			"Seccomp filters will be dumped and restored. "
			"Ensure kernel supports filter dumping (4.7+).",
			"security"
		);
		issue_add(issues, issue);
	}

	return 0;
}

/* Detect zombie process with threads */
int detect_zombie_with_threads(struct process_state *pstate,
				struct feature_results *results,
				struct issue **issues)
{
	if (pstate->is_zombie && pstate->num_threads > 1) {
		struct issue *issue = issue_new(
			ISSUE_ZOMBIE_WITH_THREADS,
			SEVERITY_CRITICAL,
			"Zombie process with multiple threads detected",
			"Zombies with threads are NOT supported by CRIU. "
			"This is a guaranteed dump failure. Clean up zombie process.",
			"process"
		);
		issue_add(issues, issue);

		results->zombie_with_threads = true;
	}

	return 0;
}

/* Detect vDSO presence */
int detect_vdso(struct vma_info *vmas, struct feature_results *results,
		struct issue **issues)
{
	bool has_vdso = false;

	for (struct vma_info *vma = vmas; vma; vma = vma->next) {
		if (vma->is_vdso) {
			has_vdso = true;
			break;
		}
	}

	if (!has_vdso) {
		/* vDSO missing - this is unusual and may indicate issues */
		struct issue *issue = issue_new(
			ISSUE_VDSO_MISSING,
			SEVERITY_WARNING,
			"vDSO (virtual dynamic shared object) not found in process memory",
			"This is unusual. Ensure kernel provides vDSO and process hasn't unmapped it. "
			"Check kernel config: CONFIG_VDSO=y",
			"memory"
		);
		issue_add(issues, issue);

		results->vdso_missing = true;
	}

	return 0;
}

/* Detect LSM (Linux Security Module) profiles */
int detect_lsm(int pid, struct feature_results *results,
	       struct issue **issues)
{
	char path[PATH_MAX];
	char *profile;

	/* Check AppArmor */
	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	profile = read_file_line(path);

	if (profile && strcmp(profile, "unconfined") != 0 && strlen(profile) > 0) {
		results->lsm_detected = true;
		strncpy(results->lsm_profile, profile, sizeof(results->lsm_profile) - 1);

		char desc[256];
		snprintf(desc, sizeof(desc),
			 "LSM profile active: %s",
			 profile);

		struct issue *issue = issue_new(
			ISSUE_LSM_DETECTED,
			SEVERITY_INFO,
			desc,
			"AppArmor/SELinux profile detected. Ensure CRIU has LSM dumping support enabled. "
			"Profile will be dumped and must be available on restore.",
			"security"
		);
		issue_add(issues, issue);
	}

	free(profile);

	return 0;
}

/* Detect AutoFS mounts */
int detect_autofs(struct mount_info *mounts, struct feature_results *results,
		  struct issue **issues)
{
	int count = 0;

	for (struct mount_info *m = mounts; m; m = m->next) {
		if (strcmp(m->fs_type, "autofs") == 0) {
			count++;
		}
	}

	if (count > 0) {
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "AutoFS mount detected - %d mount(s)",
			 count);

		struct issue *issue = issue_new(
			ISSUE_AUTOFS_DETECTED,
			SEVERITY_WARNING,
			desc,
			"AutoFS has migration limitations. Checkpoint may succeed but restore "
			"may have issues if automount paths are not available on target.",
			"filesystem"
		);
		issue_add(issues, issue);

		results->autofs_detected = true;
		results->autofs_mount_count = count;
	}

	return 0;
}

/* Detect ghost files (deleted files still open) */
int detect_ghost_files(struct fd_info *fds, struct feature_results *results,
			struct issue **issues)
{
	int count = 0;

	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		/* Check if target ends with " (deleted)" */
		size_t len = strlen(fd->target);
		if (len > 10 && strcmp(fd->target + len - 10, " (deleted)") == 0) {
			count++;
		}
	}

	if (count > 0) {
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "Ghost files detected - %d deleted file(s) still open",
			 count);

		struct issue *issue = issue_new(
			ISSUE_GHOST_FILE_DETECTED,
			SEVERITY_INFO,
			desc,
			"Process has open file descriptors to deleted files. "
			"These will be restored as anonymous inodes. Usually safe.",
			"files"
		);
		issue_add(issues, issue);

		results->ghost_files_detected = true;
		results->ghost_file_count = count;
	}

	return 0;
}

/* Detect nested PID namespace issues */
int detect_nested_pid_ns(int pid, struct namespace_info *nsinfo,
			  struct feature_results *results,
			  struct issue **issues)
{
	/* Check if process is in isolated PID namespace */
	if (!nsinfo->pid_isolated)
		return 0;

	/* Check if there are child processes that might have nested namespaces */
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);

	FILE *f = fopen(path, "r");
	if (f) {
		char *line = NULL;
		size_t len = 0;

		if (getline(&line, &len, f) != -1) {
			/* Has children - potential nested namespace issue */
			struct issue *issue = issue_new(
				ISSUE_NESTED_PID_NS,
				SEVERITY_WARNING,
				"Process in isolated PID namespace with children",
				"Nested PID namespaces may have limitations with PGID/SID restore. "
				"CRIU may not support restore of sid and pgid if nested pid namespace exists.",
				"namespace"
			);
			issue_add(issues, issue);

			results->nested_pid_ns = true;
		}

		free(line);
		fclose(f);
	}

	return 0;
}

/* Detect inotify/fanotify watches */
int detect_inotify(struct fd_info *fds, struct feature_results *results,
		   struct issue **issues)
{
	int count = 0;

	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		if (strcmp(fd->target, "anon_inode:inotify") == 0 ||
		    strcmp(fd->target, "anon_inode:[eventfd]") == 0) {
			count++;
		}
	}

	if (count > 0) {
		char desc[256];
		snprintf(desc, sizeof(desc),
			 "Inotify/Fanotify watches detected - %d watch(es)",
			 count);

		struct issue *issue = issue_new(
			ISSUE_INOTIFY_DETECTED,
			SEVERITY_INFO,
			desc,
			"File watching mechanisms detected. Inotify watches will be restored. "
			"Ensure watched paths exist on restore.",
			"files"
		);
		issue_add(issues, issue);

		results->inotify_detected = true;
		results->inotify_watch_count = count;
	}

	return 0;
}

/* Enhanced kernel feature checks */
int enhance_kernel_feature_checks(struct kernel_features *kfeatures,
				   struct issue **issues)
{
	/* Check UFFD availability */
	if (!kfeatures->has_uffd) {
		struct issue *issue = issue_new(
			ISSUE_UFFD_NOT_AVAILABLE,
			SEVERITY_INFO,
			"UFFD (userfaultfd) not available",
			"Lazy page loading (--lazy-pages) will not work. "
			"This is optional - only needed for very large memory dumps.",
			"kernel"
		);
		issue_add(issues, issue);
	}

	/* Check for /sys/kernel/mm/transparent_hugepage/enabled */
	if (file_exists("/sys/kernel/mm/transparent_hugepage/enabled")) {
		/* THP is available, good */
	} else {
		/* THP not available - may be an issue for some workloads */
	}

	return 0;
}
