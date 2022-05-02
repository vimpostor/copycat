#include "copycat.h"

#include <string.h>
#include <sys/param.h>

/*
 * Adds a rule to the rule table that maps source to dest
 * This function assumes that source and dest are not empty strings
 */
void add_rule(char *source, char *dest) {
	char *src = strdup(source);
	bool match_prefix = false;

	if (src[strlen(src) - 1] == '/') {
		// recursive mapping rule for directories
		// remove the trailing slash but set the match_prefix flag
		src[strlen(src) - 1] = '\0';
		match_prefix = true;
	}

	// actually add the rule
	rules.table[rules.size].source = src;
	rules.table[rules.size].dest = strdup(dest);
	rules.table[rules.size].match_prefix = match_prefix;
	rules.size++;
}

void parse_rule(char *line) {
	// split line into source and destination
	char *dest = strchr(line, ' ');
	if (dest != NULL) {
		// add a terminating null byte for the source string instead of the whitespace
		*dest = '\0';
		// skip ahead from the whitespace to the actual first character of destination
		dest++;

		// guard against empty strings
		if (*dest && *line) {
			add_rule(line, dest);
		}
	}
}

void parse_rules(char *rls) {
	char *line = strtok(rls, "\n");
	// split rules into lines
	while (line != NULL) {
		parse_rule(line);
		line = strtok(NULL, "\n");
	}
}

void read_config() {
	FILE *f = fopen(COPYCAT_CONFIG, "r");
	if (f == NULL) {
		return;
	}
	char *line = NULL;
	ssize_t read;
	size_t len;
	while ((read = getline(&line, &len, f)) != -1) {
		if (read > 0 && line[read - 1] == '\n') {
			// remove new line character from line
			line[read - 1] = '\0';
		}
		parse_rule(line);
	}

	free(line);
	fclose(f);
}

const char *find_match(const char *source) {
	for (size_t i = 0; i < rules.size; ++i) {
		// check if we have a recursive rule (match only prefix) or if we have to check for a literal match
		size_t chars_to_compare = strlen(rules.table[i].source);
		if (!rules.table[i].match_prefix) {
			chars_to_compare = MAX(chars_to_compare, strlen(source));
		}

		// does the rule match?
		if (!strncmp(source, rules.table[i].source, chars_to_compare)) {
			return rules.table[i].dest;
		}
	}
	return source;
}

void init() {
	copycat_env = getenv(COPYCAT_ENV);
	if (copycat_env != NULL) {
		parse_rules(copycat_env);
	} else {
		// read config file instead
		read_config();
	}

	original_calls.openat = (int (*)(int, const char *, int, mode_t)) dlsym(RTLD_NEXT, "openat");
}

void fini() {
	// free rules
	for (size_t i = 0; i < rules.size; ++i) {
		free((char *) rules.table[i].source);
		free((char *) rules.table[i].dest);
	}
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	const char *final_path = find_match(pathname);
	return original_calls.openat(dirfd, final_path, flags, mode);
}
