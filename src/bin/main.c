// needed for execvpe
#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>

#include "copycat.h"

#define MAX_ENV_SIZE 256

int main(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "")) != -1) {
		// right now we have no arguments, we only want to get the trailing argument
		(void) opt;
	}

	// copy environment to add our own
	char *env[MAX_ENV_SIZE]; //{ "LD_PRELOAD=/usr/lib/libcopycat.so", (char *)0 };
	size_t env_size = 0; // holds the size of the dynamically allocated part, the real size is 2 greater
	for (size_t i = 0; i < MAX_ENV_SIZE - 2 && environ[i] != NULL; ++i) {
		env[i] = strdup(environ[i]);
		env_size++;
	}
	// TODO: Fix the hardcoded path
	env[env_size] = "LD_PRELOAD=/usr/lib/libcopycat.so";
	env[env_size + 1] = NULL;

	int status_code = execvpe(argv[optind], argv + optind, env);

	// free environment again
	for (size_t i = 0; i < env_size; ++i) {
		free(env[i]);
	}

	return status_code;
}
