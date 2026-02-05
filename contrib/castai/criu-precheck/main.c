#include "common.h"
#include "proc_reader.h"
#include "feature_detector.h"
#include "resource_checker.h"
#include "namespace_analyzer.h"
#include "network_inspector.h"
#include "mount_analyzer.h"
#include "compatibility.h"
#include "report.h"

#include <getopt.h>

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("\n");
	printf("Pre-check CRIU checkpoint/restore compatibility for a running process.\n");
	printf("\n");
	printf("OPTIONS:\n");
	printf("  -t, --pid PID          Target process ID (required)\n");
	printf("  -j, --json             Output in JSON format\n");
	printf("  -v, --verbose          Verbose output\n");
	printf("  -o, --output FILE      Write output to file\n");
	printf("  --check-network        Check network resources only\n");
	printf("  --check-memory         Check memory resources only\n");
	printf("  --check-namespaces     Check namespaces only\n");
	printf("  --suggest-command      Suggest CRIU dump command\n");
	printf("  --exit-code-only       Exit with code indicating compatibility\n");
	printf("  -h, --help             Show this help\n");
	printf("\n");
	printf("EXIT CODES (with --exit-code-only):\n");
	printf("  0 - Very likely to succeed (90%%+)\n");
	printf("  1 - Likely to succeed (70-89%%)\n");
	printf("  2 - Uncertain (40-69%%)\n");
	printf("  3 - Unlikely to succeed (<40%%)\n");
	printf("  4 - Guaranteed to fail (critical issue detected)\n");
	printf("\n");
	printf("EXAMPLES:\n");
	printf("  %s -t 1234                   # Check PID 1234\n", prog);
	printf("  %s -t 1234 --json            # JSON output\n", prog);
	printf("  %s -t 1234 -v                # Verbose mode\n", prog);
	printf("  %s -t 1234 --exit-code-only  # Integration mode\n", prog);
	printf("\n");
}

static int parse_options(int argc, char **argv)
{
	static struct option long_options[] = {
		{ "pid", required_argument, 0, 't' },
		{ "json", no_argument, 0, 'j' },
		{ "verbose", no_argument, 0, 'v' },
		{ "output", required_argument, 0, 'o' },
		{ "check-network", no_argument, 0, 'n' },
		{ "check-memory", no_argument, 0, 'm' },
		{ "check-namespaces", no_argument, 0, 's' },
		{ "suggest-command", no_argument, 0, 'c' },
		{ "exit-code-only", no_argument, 0, 'e' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	int c;
	while ((c = getopt_long(argc, argv, "t:jvo:h", long_options, NULL)) != -1) {
		switch (c) {
		case 't':
			if (safe_atoi(optarg, &opts.pid) < 0) {
				pr_err("Invalid PID: %s\n", optarg);
				return -1;
			}
			break;
		case 'j':
			opts.json = true;
			break;
		case 'v':
			opts.verbose = true;
			break;
		case 'o':
			strncpy(opts.output_file, optarg, sizeof(opts.output_file) - 1);
			break;
		case 'n':
			opts.check_network = true;
			break;
		case 'm':
			opts.check_memory = true;
			break;
		case 's':
			opts.check_namespaces = true;
			break;
		case 'c':
			opts.suggest_command = true;
			break;
		case 'e':
			opts.exit_code_only = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (opts.pid <= 0) {
		pr_err("PID is required. Use -t/--pid option.\n");
		usage(argv[0]);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct process_state pstate = { 0 };
	struct vma_info *vmas = NULL;
	struct fd_info *fds = NULL;
	struct namespace_info nsinfo = { 0 };
	struct mount_info *mounts = NULL;
	struct issue *issues = NULL;
	struct feature_results features = { 0 };
	struct resource_summary resources = { 0 };
	struct compatibility_score compat = { 0 };
	unsigned long total_private_kb = 0;
	int ret = 1;

	/* Parse command-line options */
	if (parse_options(argc, argv) < 0)
		return 1;

	/* Check if process exists */
	char proc_path[PATH_MAX];
	snprintf(proc_path, sizeof(proc_path), "/proc/%d", opts.pid);
	if (!dir_exists(proc_path)) {
		pr_err("Process %d does not exist\n", opts.pid);
		return 1;
	}

	pr_debug("Checking process %d\n", opts.pid);

	/* Parse process state */
	if (parse_process_state(opts.pid, &pstate) < 0) {
		pr_err("Failed to parse process state\n");
		goto out;
	}

	pr_debug("Process state: %s (%c)\n", pstate.comm, pstate.state);

	/* Parse VMAs */
	if (parse_vma_list(opts.pid, &vmas, &total_private_kb) < 0) {
		pr_err("Failed to parse memory mappings\n");
		goto out;
	}

	pr_debug("Parsed %lu KB private memory\n", total_private_kb);

	/* Parse file descriptors */
	if (parse_fd_list(opts.pid, &fds) < 0) {
		pr_err("Failed to parse file descriptors\n");
		goto out;
	}

	/* Parse namespaces */
	if (parse_namespaces(opts.pid, &nsinfo) < 0) {
		pr_err("Failed to parse namespaces\n");
		goto out;
	}

	/* Parse mounts (optional) */
	parse_mounts(opts.pid, &mounts);

	/* Check kernel features */
	if (check_kernel_features(&features.kfeatures) < 0) {
		pr_warn("Failed to detect some kernel features\n");
	}

	/* Run feature detectors */
	detect_io_uring(fds, vmas, &features, &issues);
	detect_rseq_usage(opts.pid, vmas, &features, &issues);
	detect_network_features(opts.pid, fds, &features, &issues);
	detect_sysvipc_issues(vmas, &nsinfo, &features, &issues);
	check_aio_ring_alignment(vmas, &features, &issues);
	detect_multithreading(opts.pid, &features, &issues);
	detect_mptcp(opts.pid, &features, &issues);
	detect_tty(fds, &features, &issues);
	detect_seccomp(opts.pid, &features, &issues);
	detect_zombie_with_threads(&pstate, &features, &issues);
	detect_vdso(vmas, &features, &issues);
	detect_lsm(opts.pid, &features, &issues);

	/* Phase 2 checks */
	detect_autofs(mounts, &features, &issues);
	detect_ghost_files(fds, &features, &issues);
	detect_nested_pid_ns(opts.pid, &nsinfo, &features, &issues);
	detect_inotify(fds, &features, &issues);
	enhance_kernel_feature_checks(&features.kfeatures, &issues);

	/* Check process resources */
	check_process_resources(opts.pid, &pstate, vmas, fds, &resources, &issues);

	/* Analyze namespaces */
	analyze_namespaces(&nsinfo, &issues);

	/* Inspect network (additional checks) */
	inspect_network(opts.pid, fds, &issues);

	/* Analyze mounts */
	analyze_mounts(opts.pid, mounts, &issues);

	/* Calculate compatibility score */
	calculate_compatibility(issues, &compat);

	/* Print report */
	if (opts.json) {
		print_json_report(opts.pid, &pstate, &resources, &nsinfo,
				  &features, issues, &compat);
	} else if (!opts.exit_code_only) {
		print_report(opts.pid, &pstate, &resources, &nsinfo,
			     &features, issues, &compat);
	}

	/* Exit code */
	if (opts.exit_code_only) {
		if (compat.score >= 90)
			ret = 0;
		else if (compat.score >= 70)
			ret = 1;
		else if (compat.score >= 40)
			ret = 2;
		else if (compat.score > 0)
			ret = 3;
		else
			ret = 4; /* Guaranteed fail */
	} else {
		ret = 0; /* Success - report generated */
	}

out:
	/* Cleanup */
	free_vma_list(vmas);
	free_fd_list(fds);
	free_mount_list(mounts);
	issue_free_all(issues);

	return ret;
}
