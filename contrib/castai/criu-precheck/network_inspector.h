#ifndef CRIU_PRECHECK_NETWORK_INSPECTOR_H
#define CRIU_PRECHECK_NETWORK_INSPECTOR_H

#include "common.h"
#include "proc_reader.h"

int inspect_network(int pid, struct fd_info *fds, struct issue **issues);

#endif /* CRIU_PRECHECK_NETWORK_INSPECTOR_H */
