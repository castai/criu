#ifndef CRIU_PRECHECK_COMPATIBILITY_H
#define CRIU_PRECHECK_COMPATIBILITY_H

#include "common.h"

struct compatibility_score {
	int score;	   /* 0-100 */
	const char *level; /* "very_likely", "likely", "uncertain", "unlikely" */
	int passed;
	int warnings;
	int critical;
};

int calculate_compatibility(struct issue *issues, struct compatibility_score *compat);

#endif /* CRIU_PRECHECK_COMPATIBILITY_H */
