#ifndef CRIU_PRECHECK_COMMON_H
#define CRIU_PRECHECK_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

/* Color codes for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_BOLD    "\033[1m"

/* Logging macros */
#define pr_err(fmt, ...)    fprintf(stderr, COLOR_RED "ERROR: " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...)   fprintf(stderr, COLOR_YELLOW "WARN: " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...)   fprintf(stdout, COLOR_BLUE "INFO: " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define pr_debug(fmt, ...)  do { if (opts.verbose) fprintf(stdout, "DEBUG: " fmt "\n", ##__VA_ARGS__); } while(0)

/* Issue severity levels */
enum severity {
	SEVERITY_INFO = 0,
	SEVERITY_WARNING,
	SEVERITY_CRITICAL,
};

/* Issue types */
enum issue_type {
	ISSUE_IO_URING_DETECTED,
	ISSUE_RSEQ_NO_KERNEL_SUPPORT,
	ISSUE_SYSVIPC_NO_IPC_NS,
	ISSUE_INVALID_SESSION,
	ISSUE_ZOMBIE_PROCESS,
	ISSUE_STOPPED_PROCESS,
	ISSUE_TCP_ESTABLISHED,
	ISSUE_EXTERNAL_MOUNT,
	ISSUE_RSEQ_LIKELY,
	ISSUE_MULTITHREADED,
	ISSUE_MISSING_KERNEL_FEATURE,
	ISSUE_AIO_RING_MISALIGNED,
	ISSUE_MPTCP_DETECTED,
	ISSUE_TTY_DETECTED,
	ISSUE_SECCOMP_NO_KERNEL_SUPPORT,
	ISSUE_ZOMBIE_WITH_THREADS,
	ISSUE_VDSO_MISSING,
	ISSUE_LSM_DETECTED,
	ISSUE_AUTOFS_DETECTED,
	ISSUE_GHOST_FILE_DETECTED,
	ISSUE_NESTED_PID_NS,
	ISSUE_UFFD_NOT_AVAILABLE,
	ISSUE_INOTIFY_DETECTED,
	ISSUE_MAX,
};

/* Issue structure */
struct issue {
	enum issue_type type;
	enum severity severity;
	char description[256];
	char recommendation[512];
	char affected_resource[128];
	struct issue *next;
};

/* Global options */
struct options {
	int pid;
	bool json;
	bool verbose;
	bool check_network;
	bool check_memory;
	bool check_namespaces;
	bool suggest_command;
	bool exit_code_only;
	char output_file[PATH_MAX];
};

extern struct options opts;

/* Issue list management */
struct issue *issue_new(enum issue_type type, enum severity severity,
			const char *description, const char *recommendation,
			const char *affected_resource);
void issue_add(struct issue **head, struct issue *issue);
void issue_free_all(struct issue *head);
int issue_count_by_severity(struct issue *head, enum severity sev);

/* Utility functions */
char *read_file_line(const char *path);
int read_file_int(const char *path, int *value);
bool file_exists(const char *path);
bool dir_exists(const char *path);
int safe_atoi(const char *str, int *out);
unsigned long parse_size(const char *str);

#endif /* CRIU_PRECHECK_COMMON_H */
