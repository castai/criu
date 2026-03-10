#include "report.h"

static const char *severity_str(enum severity sev)
{
	switch (sev) {
	case SEVERITY_CRITICAL:
		return "CRITICAL";
	case SEVERITY_WARNING:
		return "WARNING";
	case SEVERITY_INFO:
		return "INFO";
	default:
		return "UNKNOWN";
	}
}

static const char *severity_symbol(enum severity sev)
{
	switch (sev) {
	case SEVERITY_CRITICAL:
		return COLOR_RED "❌" COLOR_RESET;
	case SEVERITY_WARNING:
		return COLOR_YELLOW "⚠️ " COLOR_RESET;
	case SEVERITY_INFO:
		return COLOR_GREEN "✅" COLOR_RESET;
	default:
		return "?";
	}
}

int print_report(int pid, struct process_state *pstate,
		 struct resource_summary *resources,
		 struct namespace_info *nsinfo,
		 struct feature_results *features,
		 struct issue *issues,
		 struct compatibility_score *compat)
{
	printf("\n");
	printf(COLOR_BOLD "CRIU Pre-Check Report for PID %d\n" COLOR_RESET, pid);
	printf("====================================\n\n");

	/* Process info */
	printf(COLOR_BOLD "PROCESS INFO:\n" COLOR_RESET);
	printf("  Command:     %s\n", pstate->comm);
	printf("  State:       %c (%s)\n", pstate->state,
	       pstate->state == 'R' ? "Running" :
	       pstate->state == 'S' ? "Sleeping" :
	       pstate->state == 'D' ? "Disk sleep" :
	       pstate->state == 'Z' ? "Zombie" :
	       pstate->state == 'T' ? "Stopped" :
				      "Unknown");
	printf("  Threads:     %d\n", pstate->num_threads);
	printf("  Session:     %d %s\n", pstate->sid,
	       pstate->sid == 0 ? COLOR_RED "(invalid!)" COLOR_RESET : "(valid)");
	printf("\n");

	/* Compatibility */
	const char *compat_color = COLOR_GREEN;
	if (compat->score < 70)
		compat_color = COLOR_YELLOW;
	if (compat->score < 40)
		compat_color = COLOR_RED;

	printf(COLOR_BOLD "COMPATIBILITY: " COLOR_RESET);
	printf("%s%d%% %s\n" COLOR_RESET, compat_color, compat->score,
	       compat->level);
	printf("  ✅ PASSED: %d checks\n", compat->passed);
	printf("  ⚠️  WARNINGS: %d checks\n", compat->warnings);
	printf("  ❌ FAILED: %d checks\n", compat->critical);
	printf("\n");

	/* Issues */
	if (compat->critical > 0) {
		printf(COLOR_BOLD COLOR_RED "CRITICAL ISSUES:\n" COLOR_RESET);
		for (struct issue *i = issues; i; i = i->next) {
			if (i->severity == SEVERITY_CRITICAL) {
				printf("  %s %s\n", severity_symbol(i->severity), i->description);
				printf("     → RECOMMENDATION: %s\n", i->recommendation);
				if (i->affected_resource[0])
					printf("     → AFFECTED: %s\n", i->affected_resource);
				printf("\n");
			}
		}
	}

	if (compat->warnings > 0) {
		printf(COLOR_BOLD "WARNINGS:\n" COLOR_RESET);
		for (struct issue *i = issues; i; i = i->next) {
			if (i->severity == SEVERITY_WARNING) {
				printf("  %s %s\n", severity_symbol(i->severity), i->description);
				printf("     → RECOMMENDATION: %s\n", i->recommendation);
				printf("\n");
			}
		}
	}

	/* Resource summary */
	printf(COLOR_BOLD "RESOURCE SUMMARY:\n" COLOR_RESET);
	printf("  Memory:\n");
	printf("    - VMAs: %d\n", resources->vma_count);
	printf("    - Private pages: ~%lu MB\n", resources->private_mb);
	printf("    - Shared pages: ~%lu MB\n", resources->shared_mb);
	if (features->io_uring_count > 0)
		printf("    - AIO rings: %d (io_uring)\n", features->io_uring_count);
	printf("\n");

	printf("  File Descriptors: %d\n", resources->fd_count);
	printf("    - Regular files: %d\n", resources->regular_file_count);
	printf("    - Sockets: %d", resources->socket_count);
	if (features->tcp_established_count > 0)
		printf(" (%d TCP ESTABLISHED)", features->tcp_established_count);
	printf("\n");
	printf("    - Special: %d", resources->special_fd_count);
	if (features->io_uring_detected)
		printf(" (includes io_uring)");
	printf("\n\n");

	printf("  Namespaces:\n");
	printf("    - PID namespace: %s (ino:%llu)\n",
	       nsinfo->pid_isolated ? "isolated" : "default", (unsigned long long)nsinfo->pid_ns);
	printf("    - Network namespace: %s (ino:%llu)\n",
	       nsinfo->net_isolated ? "isolated" : "default", (unsigned long long)nsinfo->net_ns);
	printf("    - Mount namespace: %s (ino:%llu)\n",
	       nsinfo->mnt_isolated ? "isolated" : "default", (unsigned long long)nsinfo->mnt_ns);
	printf("    - IPC namespace: %s (ino:%llu)\n",
	       nsinfo->ipc_isolated ? "isolated" : "default", (unsigned long long)nsinfo->ipc_ns);
	printf("\n");

	/* Kernel features */
	printf(COLOR_BOLD "KERNEL FEATURES:\n" COLOR_RESET);
	printf("  %s tcp_repair\n",
	       features->kfeatures.has_tcp_repair ? "✅" : "❌");
	printf("  %s ptrace_get_rseq_conf\n",
	       features->kfeatures.has_ptrace_get_rseq_conf ? "✅" : "❌");
	printf("  %s userns\n",
	       features->kfeatures.has_userns ? "✅" : "❌");
	printf("  %s memfd\n",
	       features->kfeatures.has_memfd ? "✅" : "❌");
	printf("\n");

	return 0;
}

int print_json_report(int pid, struct process_state *pstate,
		      struct resource_summary *resources,
		      struct namespace_info *nsinfo,
		      struct feature_results *features,
		      struct issue *issues,
		      struct compatibility_score *compat)
{
	(void)nsinfo; /* Not fully used in JSON output yet */
	printf("{\n");
	printf("  \"pid\": %d,\n", pid);
	printf("  \"process\": {\n");
	printf("    \"command\": \"%s\",\n", pstate->comm);
	printf("    \"state\": \"%c\",\n", pstate->state);
	printf("    \"ppid\": %d,\n", pstate->ppid);
	printf("    \"pgid\": %d,\n", pstate->pgid);
	printf("    \"sid\": %d,\n", pstate->sid);
	printf("    \"threads\": %d,\n", pstate->num_threads);
	printf("    \"is_zombie\": %s,\n", pstate->is_zombie ? "true" : "false");
	printf("    \"is_stopped\": %s\n", pstate->is_stopped ? "true" : "false");
	printf("  },\n");

	printf("  \"compatibility\": {\n");
	printf("    \"score\": %d,\n", compat->score);
	printf("    \"level\": \"%s\",\n", compat->level);
	printf("    \"passed\": %d,\n", compat->passed);
	printf("    \"warnings\": %d,\n", compat->warnings);
	printf("    \"failed\": %d\n", compat->critical);
	printf("  },\n");

	printf("  \"issues\": {\n");
	printf("    \"critical\": [\n");
	bool first = true;
	for (struct issue *i = issues; i; i = i->next) {
		if (i->severity == SEVERITY_CRITICAL) {
			if (!first)
				printf(",\n");
			printf("      {\n");
			printf("        \"type\": \"%s\",\n", severity_str(i->severity));
			printf("        \"description\": \"%s\",\n", i->description);
			printf("        \"recommendation\": \"%s\"", i->recommendation);
			if (i->affected_resource[0])
				printf(",\n        \"affected_resource\": \"%s\"", i->affected_resource);
			printf("\n      }");
			first = false;
		}
	}
	printf("\n    ],\n");

	printf("    \"warnings\": [\n");
	first = true;
	for (struct issue *i = issues; i; i = i->next) {
		if (i->severity == SEVERITY_WARNING) {
			if (!first)
				printf(",\n");
			printf("      {\n");
			printf("        \"type\": \"%s\",\n", severity_str(i->severity));
			printf("        \"description\": \"%s\",\n", i->description);
			printf("        \"recommendation\": \"%s\"\n", i->recommendation);
			printf("      }");
			first = false;
		}
	}
	printf("\n    ]\n");
	printf("  },\n");

	printf("  \"resources\": {\n");
	printf("    \"memory\": {\n");
	printf("      \"vmas\": %d,\n", resources->vma_count);
	printf("      \"private_mb\": %lu,\n", resources->private_mb);
	printf("      \"shared_mb\": %lu\n", resources->shared_mb);
	printf("    },\n");
	printf("    \"file_descriptors\": {\n");
	printf("      \"total\": %d,\n", resources->fd_count);
	printf("      \"regular\": %d,\n", resources->regular_file_count);
	printf("      \"sockets\": %d,\n", resources->socket_count);
	printf("      \"special\": %d\n", resources->special_fd_count);
	printf("    },\n");
	printf("    \"network\": {\n");
	printf("      \"tcp_established\": %d\n", features->tcp_established_count);
	printf("    }\n");
	printf("  }\n");

	printf("}\n");

	return 0;
}
