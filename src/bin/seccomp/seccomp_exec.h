#include <stdio.h>
#include <seccomp.h>
#include <sys/types.h>
#include <unistd.h>

#include "seccomp_trap.h"

struct seccomp_state {
	int sk_pair[2];
	int listener;
	pid_t task_pid;
};

int seccomp_child(const char *file, char *const argv[], struct seccomp_state *state);
int seccomp_parent(struct seccomp_state *state);
int seccomp_exec(const char *file, char *const argv[]);
