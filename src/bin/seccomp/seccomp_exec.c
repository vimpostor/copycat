#include "seccomp_exec.h"

#include <linux/openat2.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "syscalls/openat2.h"

// list of all syscalls to trap
static const int scalls[] = {
	__NR_openat,
	__NR_openat2,
};

void handle_child_exit(int) {
	// For now ok like this...
	// Ideally we want to perform the cleanup in a more elegant way, than just straight up exiting.
	// But there are bugs, that cause ioctl(SECCOMP_IOCTL_NOTIF_ADDFD) to block forever when the child exits,
	// so it is easier for now to do it this way.
	exit(0);
}

int seccomp_child(const char *file, char *const argv[], struct seccomp_state *state) {
	// agree to not gain any new privs, see man 2 seccomp section SECCOMP_SET_MODE_FILTER
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	state->listener = user_trap_syscalls(scalls, ARRAY_SIZE(scalls), SECCOMP_FILTER_FLAG_NEW_LISTENER);
	// check if syscall trap setup was successful
	if (state->listener < 0) {
		perror("user_trap_syscalls");
		return -1;
	}

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

	// install a signal handler so that we can quit the supervisor, once the target has terminated
	struct sigaction sa;
	sa.sa_handler = handle_child_exit;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction(SIGCHLD)");
		return -1;
	}

	// setup supervisor
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

int handle_req(struct seccomp_notif *req,
		      struct seccomp_notif_resp *resp, int listener)
{
	char path[PATH_MAX];
	int ret = -1, mem;

	int dirfd;
	char pathname[PATH_MAX];
	int flags;
	mode_t mode;

	int nr = req->data.nr;

	resp->id = req->id;
	resp->error = -EPERM;
	resp->val = 0;

#ifndef NDEBUG
	bool found = false;
	for (int i = 0; i < ARRAY_SIZE(scalls); ++i) {
		if (req->data.nr == scalls[i]) {
			found = true;
		}
	}
	if (!found) {
		fprintf(stderr, "huh? trapped system call %d that does not appear on our list?\n", req->data.nr);
		if (0) {
			// TODO: Continue the syscall normally if nothing matches
			resp->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		}
		return -1;
	}
#endif

	/*
	 * Ok, let's read the task's memory to see what they wanted to open
	 */
	snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
	mem = open(path, O_RDONLY);
	if (mem < 0) {
		perror("open mem");
		return -1;
	}

	/*
	 * Now we avoid a TOCTOU: we referred to a pid by its pid, but since
	 * the pid that made the syscall may have died, we need to confirm that
	 * the pid is still valid after we open its /proc/pid/mem file. We can
	 * ask the listener fd this as follows.
	 *
	 * Note that this check should occur *after* any task-specific
	 * resources are opened, to make sure that the task has not died and
	 * we're not wrongly reading someone else's state in order to make
	 * decisions.
	 */
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) < 0) {
		fprintf(stderr, "task died before we could map its memory\n");
		goto out;
	}

	/*
	 * Phew, we've got the right /proc/pid/mem. Now we can read it. Note
	 * that to avoid another TOCTOU, we should read all of the pointer args
	 * before we decide to allow the syscall.
	 */
	dirfd = ls_int(req->data.args[0]);

	ret = pread(mem, pathname, sizeof(pathname), req->data.args[1]);
	if (ret < 0) {
		perror("pread");
		goto out;
	}

	flags = ls_int(req->data.args[2]);
	mode = (mode_t) ls_int(req->data.args[3]);

	// Make the final system call
	// This will resolve to our overloaded syscall
	if (nr == __NR_openat) {
		ret = openat(dirfd, pathname, flags, mode);
	} else if (nr == __NR_openat2) {
		struct open_how how;
		how.flags = 0;
		how.mode = 0;
		how.resolve = 0;
		// TODO: Actually pass a how struct
		ret = openat2(dirfd, pathname, &how, sizeof(struct open_how));
	}

	if (ret == -1) {
		ret = 0;
	} else {
		// inject the file descriptor into the target process
		struct seccomp_notif_addfd addfd = {};
		addfd.id = req->id;
		addfd.flags = 0;
		addfd.srcfd = ret;
		ret = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
		if (ret == -1) {
			perror("SECCOMP_IOCTL_NOTIF_ADDFD");
			goto out;
		}
		resp->error = 0;
	}
out:
	close(mem);
	return ret;
}
