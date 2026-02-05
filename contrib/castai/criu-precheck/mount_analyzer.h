#ifndef CRIU_PRECHECK_MOUNT_ANALYZER_H
#define CRIU_PRECHECK_MOUNT_ANALYZER_H

#include "common.h"
#include "proc_reader.h"

int analyze_mounts(int pid, struct mount_info *mounts, struct issue **issues);

#endif /* CRIU_PRECHECK_MOUNT_ANALYZER_H */
