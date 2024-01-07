#include "copycat.h"

#include <string.h>
#include <sys/param.h>

#define COPYCAT_ENV "COPYCAT"
char *copycat_env;

#define COPYCAT_CONFIG ".copycat.conf"

char path_buffer[PATH_MAX];

struct original_calls original_calls = {};

#define MAX_RULES_SIZE 64
struct rule_t {
	const char *source;
	const char *dest;
	bool match_prefix;
	bool replace_prefix_only;
};
struct rules_t {
	size_t size;
	struct rule_t table[MAX_RULES_SIZE];
} rules = {0};

/*
 * Adds a rule to the rule table that maps source to destination
 * This function assumes that source and destination are not empty strings
 */
void add_rule(char *source, char *destination) {
	char *src = strdup(source);
	char *dest = strdup(destination);
	bool match_prefix = false;
	bool replace_prefix_only = false;

	if (src[strlen(src) - 1] == '/') {
		// recursive mapping rule for directories
		// remove the trailing slash but set the match_prefix flag
		src[strlen(src) - 1] = '\0';
		match_prefix = true;
	}

	if (dest[strlen(dest) - 1] == '/') {
		// trailing slash in destination
		// replace prefix only
		dest[strlen(dest) - 1] = '\0';
		replace_prefix_only = true;
	}

	// actually add the rule
	rules.table[rules.size].source = src;
	rules.table[rules.size].dest = dest;
	rules.table[rules.size].match_prefix = match_prefix;
	rules.table[rules.size].replace_prefix_only = replace_prefix_only;
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
		size_t rulesrc_len = strlen(rules.table[i].source);
		// check if we have a recursive rule (match only prefix) or if we have to check for a literal match
		size_t chars_to_compare = rulesrc_len;
		if (!rules.table[i].match_prefix) {
			chars_to_compare = MAX(chars_to_compare, strlen(source));
		}

		// does the rule match?
		if (!strncmp(source, rules.table[i].source, chars_to_compare)) {
			char *result = (char *) rules.table[i].dest;
			if (rules.table[i].replace_prefix_only) {
				// extend result with rest of the input source
				// this means we have just replaced the prefix
				strcpy(path_buffer, result);
				result = path_buffer;
				strcat(result, source + rulesrc_len);
			}
			return result;
		}
	}
	return source;
}


long original_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size) {
	/**
	 * glibc currently does not wrap openat2
	 * Therefore we must manually implement it via syscall
	 */
	return syscall(SYS_openat2, dirfd, pathname, how, size);
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
	original_calls.openat2 = &original_openat2;
}

void fini() {
	// free rules
	for (size_t i = 0; i < rules.size; ++i) {
		free((char *) rules.table[i].source);
		free((char *) rules.table[i].dest);
	}
}
