#include "copycat.h"

void parse_rule(char *line) {
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
		if (!strcmp(source, rules.table[i].source)) {
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
