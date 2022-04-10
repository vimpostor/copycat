// needed for dlfcn.h RTLD_NEXT definition
#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define COPYCAT_ENV "COPYCAT"
char *copycat_env;

#define MAX_RULES_SIZE 64
struct rule_t {
	const char *source;
	const char *dest;
};
struct rules_t {
	size_t size;
	struct rule_t table[MAX_RULES_SIZE];
} rules = {0};

struct original_calls {
	int (*openat)(int dirfd, const char *pathname, int flags, mode_t mode);
} original_calls;

void parse_rules(char *rls);
void init() __attribute__((constructor));
void fini() __attribute__((destructor));
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
