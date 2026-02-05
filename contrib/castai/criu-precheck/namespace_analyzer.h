#ifndef CRIU_PRECHECK_NAMESPACE_ANALYZER_H
#define CRIU_PRECHECK_NAMESPACE_ANALYZER_H

#include "common.h"
#include "proc_reader.h"

int analyze_namespaces(struct namespace_info *nsinfo, struct issue **issues);

#endif /* CRIU_PRECHECK_NAMESPACE_ANALYZER_H */
