#include "ld_preload.h"

#define MAX_ENV_SIZE 256

int ld_exec(const char *file, char *const argv[]) {
	// copy environment to add our own variable
	char *env[MAX_ENV_SIZE];
	size_t env_size = 0; // holds the size of the dynamically allocated part, the real size is 2 greater
	for (size_t i = 0; i < MAX_ENV_SIZE - 2 && environ[i] != NULL; ++i) {
		env[i] = strdup(environ[i]);
		env_size++;
	}
	env[env_size] = "LD_PRELOAD=/usr/lib/libcopycat.so"; // TODO: Fix the hardcoded path
	env[env_size + 1] = NULL;

	int status_code = execvpe(file, argv, env);

	// if we reach this, then execvp failed
	perror(file);

	// free environment again
	for (size_t i = 0; i < env_size; ++i) {
		free(env[i]);
	}
	return status_code;
}
