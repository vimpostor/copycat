#include <getopt.h>

#include "copycat.h"
#include "ld_preload.h"
#include "seccomp/seccomp_exec.h"

void show_usage() {
	printf("Usage: copycat /path/to/program\n");
}

int main(int argc, char *argv[])
{
	// parse args
	bool use_seccomp = true;
	bool show_help = false;
	int opt;
	static struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "no-seccomp", no_argument, NULL, 'n' },
		{ NULL, 0, NULL, 0 }
	};
	while ((opt = getopt_long(argc, argv, "hn", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			show_help = true;
			break;
		case 'n':
			use_seccomp = false;
			break;
		case '?':
			show_help = true;
			break;
		default:
			fprintf(stderr, "?? getopt returned character code 0%o ??\n", opt);
			show_help = true;
		}
	}

	int status_code = EXIT_SUCCESS;
	if (show_help || argv[optind] == NULL) {
		show_usage();
	} else {
		// actually run the executable
		const char *program = argv[optind];
		char **const program_args = argv + optind;
		if (use_seccomp) {
			// seccomp
			status_code = seccomp_exec(program, program_args);
		} else {
			// LD_PRELOAD
			status_code = ld_exec(program, program_args);
		}
	}

	return status_code;
}
