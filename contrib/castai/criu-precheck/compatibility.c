#include "compatibility.h"

int calculate_compatibility(struct issue *issues, struct compatibility_score *compat)
{
	int score = 100;
	int passed = 0, warnings = 0, critical = 0;

	/* Count issues by severity */
	for (struct issue *i = issues; i; i = i->next) {
		switch (i->severity) {
		case SEVERITY_CRITICAL:
			critical++;
			/* Critical issues heavily penalize score */
			switch (i->type) {
			case ISSUE_IO_URING_DETECTED:
				score -= 50;
				break;
			case ISSUE_RSEQ_NO_KERNEL_SUPPORT:
			case ISSUE_SYSVIPC_NO_IPC_NS:
			case ISSUE_INVALID_SESSION:
			case ISSUE_ZOMBIE_PROCESS:
			case ISSUE_MPTCP_DETECTED:
			case ISSUE_ZOMBIE_WITH_THREADS:
			case ISSUE_SECCOMP_NO_KERNEL_SUPPORT:
				score = 0; /* Guaranteed failure */
				break;
			case ISSUE_STOPPED_PROCESS:
				score -= 80;
				break;
			case ISSUE_AIO_RING_MISALIGNED:
				score -= 40;
				break;
			case ISSUE_TTY_DETECTED:
				score -= 10; /* TTY needs careful handling */
				break;
			case ISSUE_VDSO_MISSING:
				score -= 15; /* Unusual, likely problematic */
				break;
			default:
				score -= 30;
			}
			break;

		case SEVERITY_WARNING:
			warnings++;
			/* Specific warnings have different impacts */
			switch (i->type) {
			case ISSUE_AUTOFS_DETECTED:
			case ISSUE_NESTED_PID_NS:
				score -= 8; /* More impactful warnings */
				break;
			default:
				score -= 5;
			}
			break;

		case SEVERITY_INFO:
			passed++;
			/* Info messages have minimal impact */
			switch (i->type) {
			case ISSUE_GHOST_FILE_DETECTED:
			case ISSUE_INOTIFY_DETECTED:
			case ISSUE_UFFD_NOT_AVAILABLE:
				score -= 0; /* Informational only, no penalty */
				break;
			default:
				score -= 1;
			}
			break;
		}
	}

	/* Ensure score stays in bounds */
	if (score < 0)
		score = 0;

	compat->score = score;
	compat->passed = passed;
	compat->warnings = warnings;
	compat->critical = critical;

	/* Determine level */
	if (score >= 90)
		compat->level = "very_likely";
	else if (score >= 70)
		compat->level = "likely";
	else if (score >= 40)
		compat->level = "uncertain";
	else
		compat->level = "unlikely";

	return 0;
}
