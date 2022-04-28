#include <sys/types.h>
#include <unistd.h>

int ptrace_exec(const char *file, char *const argv[]);
