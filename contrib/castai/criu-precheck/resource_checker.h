#ifndef CRIU_PRECHECK_RESOURCE_CHECKER_H
#define CRIU_PRECHECK_RESOURCE_CHECKER_H

#include "common.h"
#include "proc_reader.h"

struct resource_summary {
	int vma_count;
	unsigned long private_mb;
	unsigned long shared_mb;
	int fd_count;
	int regular_file_count;
	int socket_count;
	int special_fd_count;
};

int check_process_resources(int pid, struct process_state *pstate,
			    struct vma_info *vmas, struct fd_info *fds,
			    struct resource_summary *summary,
			    struct issue **issues);

#endif /* CRIU_PRECHECK_RESOURCE_CHECKER_H */
