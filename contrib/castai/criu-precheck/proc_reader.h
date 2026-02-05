#ifndef CRIU_PRECHECK_PROC_READER_H
#define CRIU_PRECHECK_PROC_READER_H

#include "common.h"
#include <sys/types.h>

/* Process state from /proc/PID/stat */
struct process_state {
	int pid;
	char comm[256];
	char state;		/* R, S, D, Z, T, etc. */
	int ppid;
	int pgid;
	int sid;
	int num_threads;
	unsigned long start_code;
	unsigned long end_code;
	unsigned long start_stack;
	unsigned long start_data;
	unsigned long end_data;
	unsigned long start_brk;
	bool is_zombie;
	bool is_stopped;
	bool is_session_leader;
};

/* VMA (Virtual Memory Area) information from /proc/PID/smaps */
enum vma_type {
	VMA_REGULAR = 0,
	VMA_SYSVIPC,
	VMA_SOCKET,
	VMA_AIORING,
};

struct vma_info {
	unsigned long start;
	unsigned long end;
	unsigned long size;
	int prot;		/* PROT_READ|WRITE|EXEC flags */
	int flags;		/* MAP_SHARED|PRIVATE flags */
	char pathname[PATH_MAX];
	enum vma_type type;
	bool is_vdso;
	bool is_executable;
	unsigned long private_kb;
	unsigned long shared_kb;
	struct vma_info *next;
};

/* File descriptor information */
struct fd_info {
	int fd_num;
	char type[32];		/* "reg", "sock", "pipe", etc. */
	char target[PATH_MAX];	/* Symlink target */
	int flags;
	bool is_io_uring;
	bool is_epoll;
	bool is_socket;
	bool is_eventfd;
	bool is_signalfd;
	bool is_timerfd;
	bool is_pidfd;
	bool is_device;
	ino_t socket_inode;
	struct fd_info *next;
};

/* Namespace information */
struct namespace_info {
	ino_t mnt_ns;
	ino_t net_ns;
	ino_t ipc_ns;
	ino_t uts_ns;
	ino_t pid_ns;
	ino_t user_ns;
	ino_t cgroup_ns;
	ino_t time_ns;
	bool mnt_isolated;
	bool net_isolated;
	bool ipc_isolated;
	bool uts_isolated;
	bool pid_isolated;
	bool user_isolated;
	bool cgroup_isolated;
	bool time_isolated;
};

/* Mount information from /proc/PID/mountinfo */
struct mount_info {
	int mnt_id;
	int parent_id;
	char dev[64];
	char root[PATH_MAX];
	char mount_point[PATH_MAX];
	char fs_type[64];
	char options[512];
	bool is_external;
	bool is_bind;
	bool is_shared;
	struct mount_info *next;
};

/* POSIX timer information */
struct timer_info {
	int id;
	char signal[32];
	char notify[32];
	int clockid;
	struct timer_info *next;
};

/* Cgroup information */
struct cgroup_info {
	int hierarchy;
	char controllers[256];
	char path[PATH_MAX];
	struct cgroup_info *next;
};

/* Function prototypes */
int parse_process_state(int pid, struct process_state *state);
int parse_vma_list(int pid, struct vma_info **vmas, unsigned long *total_private_kb);
int parse_fd_list(int pid, struct fd_info **fds);
int parse_namespaces(int pid, struct namespace_info *nsinfo);
int parse_mounts(int pid, struct mount_info **mounts);
int parse_timers(int pid, struct timer_info **timers);
int parse_cgroups(int pid, struct cgroup_info **cgroups);
int get_thread_count(int pid);
char *get_exe_path(int pid);
char *get_cwd_path(int pid);
char *get_root_path(int pid);

/* Cleanup functions */
void free_vma_list(struct vma_info *head);
void free_fd_list(struct fd_info *head);
void free_mount_list(struct mount_info *head);
void free_timer_list(struct timer_info *head);
void free_cgroup_list(struct cgroup_info *head);

#endif /* CRIU_PRECHECK_PROC_READER_H */
