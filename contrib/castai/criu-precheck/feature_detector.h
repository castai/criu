#ifndef CRIU_PRECHECK_FEATURE_DETECTOR_H
#define CRIU_PRECHECK_FEATURE_DETECTOR_H

#include "common.h"
#include "proc_reader.h"

/* Kernel feature availability */
struct kernel_features {
	bool has_rseq;
	bool has_ptrace_get_rseq_conf;
	bool has_tcp_repair;
	bool has_memfd;
	bool has_uffd;
	bool has_timens;
	bool has_userns;
	bool has_cgroupns;
	bool has_clone3_set_tid;
	bool has_pidfd_open;
	bool has_timerfd;
	bool has_kcmp;
	/* Add more as needed */
};

/* Feature detection results */
struct feature_results {
	bool io_uring_detected;
	int io_uring_count;

	bool rseq_likely;
	bool rseq_kernel_support_missing;

	bool tcp_established;
	int tcp_established_count;

	bool external_mounts;
	int external_mount_count;

	bool multithreaded;
	int thread_count;

	bool sysvipc_without_ipc_ns;

	bool aio_ring_misaligned;

	bool mptcp_detected;
	int mptcp_socket_count;

	bool tty_detected;
	int tty_count;

	bool seccomp_enabled;
	bool seccomp_kernel_support_missing;

	bool zombie_with_threads;

	bool vdso_missing;

	bool lsm_detected;
	char lsm_profile[256];

	bool autofs_detected;
	int autofs_mount_count;

	bool ghost_files_detected;
	int ghost_file_count;

	bool nested_pid_ns;

	bool inotify_detected;
	int inotify_watch_count;

	struct kernel_features kfeatures;
};

/* Function prototypes */
int detect_io_uring(struct fd_info *fds, struct vma_info *vmas,
		    struct feature_results *results, struct issue **issues);

int detect_rseq_usage(int pid, struct vma_info *vmas,
		      struct feature_results *results, struct issue **issues);

int detect_network_features(int pid, struct fd_info *fds,
			    struct feature_results *results, struct issue **issues);

int detect_sysvipc_issues(struct vma_info *vmas, struct namespace_info *nsinfo,
			  struct feature_results *results, struct issue **issues);

int check_aio_ring_alignment(struct vma_info *vmas,
			     struct feature_results *results, struct issue **issues);

int check_kernel_features(struct kernel_features *kfeatures);

int detect_multithreading(int pid, struct feature_results *results,
			  struct issue **issues);

int detect_mptcp(int pid, struct feature_results *results,
		 struct issue **issues);

int detect_tty(struct fd_info *fds, struct feature_results *results,
	       struct issue **issues);

int detect_seccomp(int pid, struct feature_results *results,
		   struct issue **issues);

int detect_zombie_with_threads(struct process_state *pstate,
			       struct feature_results *results,
			       struct issue **issues);

int detect_vdso(struct vma_info *vmas, struct feature_results *results,
		struct issue **issues);

int detect_lsm(int pid, struct feature_results *results,
	       struct issue **issues);

int detect_autofs(struct mount_info *mounts, struct feature_results *results,
		  struct issue **issues);

int detect_ghost_files(struct fd_info *fds, struct feature_results *results,
		       struct issue **issues);

int detect_nested_pid_ns(int pid, struct namespace_info *nsinfo,
			 struct feature_results *results,
			 struct issue **issues);

int detect_inotify(struct fd_info *fds, struct feature_results *results,
		   struct issue **issues);

int enhance_kernel_feature_checks(struct kernel_features *kfeatures,
				  struct issue **issues);

#endif /* CRIU_PRECHECK_FEATURE_DETECTOR_H */
