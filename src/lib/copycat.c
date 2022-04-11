#include "copycat.h"

void parse_rules(char *rls) {
	char *line = strtok(rls, "\n");
	// split rules into lines
	while (line != NULL) {
		// split line into source and destination
		char *source = NULL;
		char *dest = strchr(line, ' ');
		if (dest != NULL) {
			// add a terminating null byte for the source string instead of the whitespace
			*dest = '\0';
			source = line;
			// skip ahead from the whitespace to the actual first character of destination
			dest++;

			// add rule
			rules.table[rules.size].source = strdup(source);
			rules.table[rules.size].dest = strdup(dest);
			rules.size++;
		}
		line = strtok(NULL, "\n");
	}
}

void init() {
	copycat_env = getenv(COPYCAT_ENV);
	parse_rules(copycat_env);

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
	const char *final_path = pathname;
	for (size_t i = 0; i < rules.size; ++i) {
		if (!strcmp(final_path, rules.table[i].source)) {
			final_path = rules.table[i].dest;
			break;
		}
	}
	return original_calls.openat(dirfd, final_path, flags, mode);
}
