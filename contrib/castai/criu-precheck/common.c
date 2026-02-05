#include "common.h"
#include <sys/stat.h>
#include <ctype.h>

struct options opts = {0};

/* Create a new issue */
struct issue *issue_new(enum issue_type type, enum severity severity,
			const char *description, const char *recommendation,
			const char *affected_resource)
{
	struct issue *issue = calloc(1, sizeof(*issue));
	if (!issue)
		return NULL;

	issue->type = type;
	issue->severity = severity;
	strncpy(issue->description, description, sizeof(issue->description) - 1);
	strncpy(issue->recommendation, recommendation, sizeof(issue->recommendation) - 1);
	if (affected_resource)
		strncpy(issue->affected_resource, affected_resource, sizeof(issue->affected_resource) - 1);

	return issue;
}

/* Add issue to list */
void issue_add(struct issue **head, struct issue *issue)
{
	if (!issue)
		return;

	issue->next = *head;
	*head = issue;
}

/* Free all issues */
void issue_free_all(struct issue *head)
{
	while (head) {
		struct issue *next = head->next;
		free(head);
		head = next;
	}
}

/* Count issues by severity */
int issue_count_by_severity(struct issue *head, enum severity sev)
{
	int count = 0;
	while (head) {
		if (head->severity == sev)
			count++;
		head = head->next;
	}
	return count;
}

/* Read first line from file */
char *read_file_line(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return NULL;

	char *line = NULL;
	size_t len = 0;
	ssize_t read = getline(&line, &len, f);
	fclose(f);

	if (read <= 0) {
		free(line);
		return NULL;
	}

	/* Remove trailing newline */
	if (line[read - 1] == '\n')
		line[read - 1] = '\0';

	return line;
}

/* Read integer from file */
int read_file_int(const char *path, int *value)
{
	char *line = read_file_line(path);
	if (!line)
		return -1;

	int ret = safe_atoi(line, value);
	free(line);
	return ret;
}

/* Check if file exists */
bool file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Check if directory exists */
bool dir_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Safe string to integer conversion */
int safe_atoi(const char *str, int *out)
{
	char *endptr;
	long val;

	if (!str || !out)
		return -1;

	errno = 0;
	val = strtol(str, &endptr, 10);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
	    || (errno != 0 && val == 0)
	    || endptr == str
	    || *endptr != '\0') {
		return -1;
	}

	*out = (int)val;
	return 0;
}

/* Parse size string (e.g., "1234 kB" -> 1234) */
unsigned long parse_size(const char *str)
{
	char *endptr;
	unsigned long val;

	if (!str)
		return 0;

	val = strtoul(str, &endptr, 10);

	/* Skip whitespace */
	while (*endptr && isspace(*endptr))
		endptr++;

	/* Handle units */
	if (strncmp(endptr, "kB", 2) == 0 || strncmp(endptr, "KB", 2) == 0)
		return val;
	else if (strncmp(endptr, "MB", 2) == 0)
		return val * 1024;
	else if (strncmp(endptr, "GB", 2) == 0)
		return val * 1024 * 1024;

	return val;
}
