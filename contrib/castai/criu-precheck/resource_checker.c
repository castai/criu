#include "resource_checker.h"

int check_process_resources(int pid, struct process_state *pstate,
			    struct vma_info *vmas, struct fd_info *fds,
			    struct resource_summary *summary,
			    struct issue **issues)
{
	(void)pid;
	(void)issues;

	memset(summary, 0, sizeof(*summary));

	/* Count VMAs and memory */
	unsigned long total_private = 0, total_shared = 0;
	for (struct vma_info *vma = vmas; vma; vma = vma->next) {
		summary->vma_count++;
		total_private += vma->private_kb;
		total_shared += vma->shared_kb;
	}
	summary->private_mb = total_private / 1024;
	summary->shared_mb = total_shared / 1024;

	/* Count FDs by type */
	for (struct fd_info *fd = fds; fd; fd = fd->next) {
		summary->fd_count++;
		if (strcmp(fd->type, "reg") == 0)
			summary->regular_file_count++;
		else if (strcmp(fd->type, "sock") == 0)
			summary->socket_count++;
		else if (fd->is_io_uring || fd->is_epoll || fd->is_eventfd ||
			 fd->is_signalfd || fd->is_timerfd || fd->is_pidfd)
			summary->special_fd_count++;
	}

	/* Check process state issues */
	if (pstate->is_zombie) {
		struct issue *issue = issue_new(
			ISSUE_ZOMBIE_PROCESS,
			SEVERITY_CRITICAL,
			"Process is a zombie (state Z)",
			"Cannot checkpoint zombie process. Clean up zombie first.",
			NULL);
		issue_add(issues, issue);
	}

	if (pstate->is_stopped) {
		struct issue *issue = issue_new(
			ISSUE_STOPPED_PROCESS,
			SEVERITY_CRITICAL,
			"Process is stopped (state T)",
			"CRIU does not support checkpointing stopped processes. "
			"Resume process with SIGCONT before checkpoint.",
			NULL);
		issue_add(issues, issue);
	}

	if (pstate->sid == 0) {
		struct issue *issue = issue_new(
			ISSUE_INVALID_SESSION,
			SEVERITY_CRITICAL,
			"Process has invalid session ID (0)",
			"Session leader may be outside PID namespace. This will cause dump failure.",
			NULL);
		issue_add(issues, issue);
	}

	return 0;
}
