// needed for execvpe
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int ld_exec(const char *file, char *const argv[]);
