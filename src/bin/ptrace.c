#include "ptrace.h"

#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>

int ptrace_exec(const char *file, char *const argv[]) {
	int status_code = 0;

	// fork so that we can ptrace the new process
	pid_t pid = fork();
	if (pid) {
		// parent process / tracer
		int child_status;
		struct user_regs_struct state;
		// wait until child wants to be traced
		waitpid(pid, &child_status, 0);
		// this will cause STOPSIG to be set to 0x80 on every syscall
		ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD);
		while (!WIFEXITED(child_status)) {
			// wait for the next syscall
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			waitpid(pid, &child_status, 0);
			// ptrace will additionally stop upon receipt of a signal, so make sure that it really is a syscall
			if (WIFSTOPPED(child_status) && WSTOPSIG(child_status) == (SIGTRAP | 0x80)) {
				// retreive info about syscall
				ptrace(PTRACE_GETREGS, pid, NULL, &state);
				// this probably only works on x86 :(
				const unsigned long long syscall = state.orig_rax;
				char *path_addr;
				char *path;
				switch (syscall) {
				case SYS_openat:
					path_addr = (char *) state.rdi;
					// TODO: Somehow overwrite the path argument in the other process memory
					// Maybe something like https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/
					break;
				}

				// wait a second time for the same syscall, this time we get the return value
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				waitpid(pid, &child_status, 0);
			}
		}
	} else {
		// child process / tracee
		// tell parent that we want to be traced
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		status_code = execvp(file, argv);
	}

	return status_code;
}
