// needed for execvpe
#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>

#include "copycat.h"

#define MAX_ENV_SIZE 256

void show_usage() {
	printf("Usage: copycat /path/to/program\n");
}

int main(int argc, char *argv[])
{
	// parse args
	bool use_ptrace = true;
	bool show_help = false;
	int opt_index = 0;
	int opt;
	static struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "no-ptrace", no_argument, NULL, 'n' },
		{ NULL, 0, NULL, 0 }
	};
	while ((opt = getopt_long(argc, argv, "hn", long_opts, &opt_index)) != -1) {
		// right now we have no arguments, we only want to get the trailing argument
		switch (opt) {
		case 'h':
			show_help = true;
			break;
		case 'n':
			use_ptrace = false;
			break;
		case '?':
			show_help = true;
			break;
		default:
			fprintf(stderr, "?? getopt returned character code 0%o ??\n", opt);
			show_help = true;
		}
	}

	// copy environment to add our own
	char *env[MAX_ENV_SIZE];
	size_t env_size = 0; // holds the size of the dynamically allocated part, the real size is 2 greater
	for (size_t i = 0; i < MAX_ENV_SIZE - 2 && environ[i] != NULL; ++i) {
		env[i] = strdup(environ[i]);
		env_size++;
	}
	env[env_size] = "LD_PRELOAD=/usr/lib/libcopycat.so"; // TODO: Fix the hardcoded path
	env[env_size + 1] = NULL;

	int status_code = EXIT_SUCCESS;
	if (show_help || argv[optind] == NULL) {
		show_usage();
	} else {
		status_code = execvpe(argv[optind], argv + optind, env);
		if (status_code == -1) {
			perror(argv[optind]);
		}
	}

	// free environment again
	for (size_t i = 0; i < env_size; ++i) {
		free(env[i]);
	}

	return status_code;
}
