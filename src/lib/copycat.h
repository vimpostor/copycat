#pragma once

// needed for dlfcn.h RTLD_NEXT definition
#define _GNU_SOURCE

#include <dlfcn.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

extern struct original_calls {
	int (*open)(const char *pathname, int flags, mode_t mode);
	int (*openat)(int dirfd, const char *pathname, int flags, mode_t mode);
	long (*openat2)(int dirfd, const char *pathname, struct open_how *how, size_t size);
} original_calls;

void add_rule(char *source, char *destination);
void parse_rule(char *line);
void parse_rules(char *rls);
void read_config();
bool find_match(const char **match, const char *query);

long original_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);

void init() __attribute__((constructor));
void fini() __attribute__((destructor));
