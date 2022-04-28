#include "seccomp_exec.h"

#define __USE_POSIX
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

int seccomp_child(const char *file, char *const argv[], struct seccomp_state *state) {
	// agree to not gain any new privs, see man 2 seccomp section SECCOMP_SET_MODE_FILTER
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	state->listener = user_trap_syscall(__NR_openat, SECCOMP_FILTER_FLAG_NEW_LISTENER);
	// send the listener to the parent; also serves as synchronization
	if (send_fd(state->sk_pair[1], state->listener) < 0) {
		return -1;
	}
	close(state->listener);

	// replace with target process
	int res = execvp(file, argv);

	// if we reach this, then execvp failed
	perror(file);
	return res;
}

int seccomp_parent(struct seccomp_state *state) {
	// get the listener from the child
	state->listener = recv_fd(state->sk_pair[0]);
	if (state->listener < 0) {
		return -1;
	}

	// fork is not strictly necessary, but this way we can just wait for the tracee to exit and kill the tracer
	pid_t tracer = fork();
	if (tracer) {
		// parent
		int status, result = 0;
		close(state->listener);
		waitpid(state->task_pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			result = 1;
		}
		kill(tracer, SIGKILL);
		return result;
	} else {
		// child
		struct seccomp_notif *req;
		struct seccomp_notif_resp *resp;
		struct seccomp_notif_sizes sizes;

		if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
			perror("seccomp(GET_NOTIF_SIZES)");
			return -1;
		}
		req = malloc(sizes.seccomp_notif);
		resp = malloc(sizes.seccomp_notif_resp);
		memset(resp, 0, sizes.seccomp_notif_resp);

		while (1) {
			memset(req, 0, sizes.seccomp_notif);
			if (ioctl(state->listener, SECCOMP_IOCTL_NOTIF_RECV, req)) {
				perror("ioctl recv");
				break;
			}
			if (handle_req(req, resp, state->listener) < 0) {
				break;
			}

			// task got a signal and restarted the syscall
			if (ioctl(state->listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) {
				perror("ioctl send");
				break;
			}
		}

		// cleanup
		free(resp);
		free(req);
		close(state->listener);
		exit(EXIT_FAILURE);
	}
}

int seccomp_exec(const char *file, char *const argv[]) {
	struct seccomp_state state;
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, state.sk_pair) < 0) {
		perror("socketpair");
		return -1;
	}

	state.task_pid = fork();
	if (state.task_pid) {
		return seccomp_parent(&state);
	} else {
		return seccomp_child(file, argv, &state);
	}
}
