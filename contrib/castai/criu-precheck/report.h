#ifndef CRIU_PRECHECK_REPORT_H
#define CRIU_PRECHECK_REPORT_H

#include "common.h"
#include "proc_reader.h"
#include "resource_checker.h"
#include "feature_detector.h"
#include "compatibility.h"

int print_report(int pid, struct process_state *pstate,
		 struct resource_summary *resources,
		 struct namespace_info *nsinfo,
		 struct feature_results *features,
		 struct issue *issues,
		 struct compatibility_score *compat);

int print_json_report(int pid, struct process_state *pstate,
		      struct resource_summary *resources,
		      struct namespace_info *nsinfo,
		      struct feature_results *features,
		      struct issue *issues,
		      struct compatibility_score *compat);

#endif /* CRIU_PRECHECK_REPORT_H */
