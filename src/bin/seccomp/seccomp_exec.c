#include "seccomp_exec.h"

#include <linux/openat2.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "syscalls/openat2.h"

// list of all syscalls to trap
static const int scalls[] = {
	__NR_open,
	__NR_openat,
	__NR_openat2,
};

void handle_child_exit(int) {
	// This hacky workaround is only needed for old Linux kernel versions. With latest Linux,
	// SECCOMP_IOCTL_NOTIF_RECV will return to the caller properly once the supervised child exits.
	// But with older kernel versions there is a bug, where the call will hang indefinitely,
	// so we have to watch for the child exiting and just terminate from here as a workaround.
	// Otherwise the program would never terminate.
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
	int exit_code = EXIT_FAILURE;

	// get the listener from the child
	state->listener = recv_fd(state->sk_pair[0]);
	if (state->listener < 0) {
		return -1;
	}

	// first get a pidfd
	int pidfd = pidfd_open(state->task_pid, 0);
	if (pidfd < 0) {
		perror("pidfd_open");
		return -1;
	}

	// check for old Linux kernel version
	struct utsname uts;
	if (!uname(&uts)) {
		// to work around a Linux kernel bug, we may need to install a signal handler so that we can quit the supervisor,
		// once the target has terminated. This is not needed with Linux >= 6.11 anymore, as the bug has been fixed:
		// https://lore.kernel.org/all/20240628021014.231976-2-avagin@google.com/
		const char *version = uts.release;
		if (strverscmp(version, "6.11") < 0) {
			fprintf(stderr, "WARNING: You are using an old Linux kernel version %s, installing a fallback workaround to terminate on SIGCHLD...\n", version);
			struct sigaction sa;
			sa.sa_handler = handle_child_exit;
			sa.sa_flags = 0;
			sigemptyset(&sa.sa_mask);
			if (sigaction(SIGCHLD, &sa, NULL) == -1) {
				perror("sigaction(SIGCHLD)");
				return -1;
			}
		}
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

	while (true) {
		memset(req, 0, sizes.seccomp_notif);
		if (ioctl(state->listener, SECCOMP_IOCTL_NOTIF_RECV, req)) {
			if (errno == ENOENT) {
				// When the child exits, SECCOMP_IOCTL_NOTIF_RECV will return with ENOENT,
				// in which case we can also just quit the supervisor.
				// But first we have to retrieve the child's exit code
				int wstatus;
				pid_t wait = waitpid(state->task_pid, &wstatus, WUNTRACED | WCONTINUED);
				if (wait == state->task_pid && WIFEXITED(wstatus)) {
					// Hand over the same exit code
					exit_code = WEXITSTATUS(wstatus);
				}
			} else {
				perror("ioctl recv");
			}
			break;
		}
		if (handle_req(req, resp, state->listener, pidfd) < 0) {
			break;
		}
	}

	// cleanup
	free(resp);
	free(req);
	close(pidfd);
	close(state->listener);
	exit(exit_code);
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

bool cookie_valid(int listener, struct seccomp_notif *req) {
	return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0;
}

int pidfd_open(pid_t pid, unsigned int flags) {
	errno = 0;
	return syscall(__NR_pidfd_open, pid, flags);
}

int pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
	errno = 0;
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

int handle_req(struct seccomp_notif *req,
		      struct seccomp_notif_resp *resp, int listener, int pidfd)
{
	char path[PATH_MAX];
	int ret = -1, mem;

	int dirfd = -1, proxy_dirfd = -1;
	char pathname[PATH_MAX];
	const char *proxy_pathname = NULL;
	int flags;
	mode_t mode;
	struct open_how how;

	int nr = req->data.nr;

	resp->id = req->id;
	resp->error = -EPERM;
	resp->val = 0;
	resp->flags = 0;

#ifndef NDEBUG
	bool found = false;
	for (int i = 0; i < ARRAY_SIZE(scalls); ++i) {
		if (req->data.nr == scalls[i]) {
			found = true;
		}
	}
	if (!found) {
		fprintf(stderr, "huh? trapped system call %d that does not appear on our list?\n", req->data.nr);
		// continue the syscall normally
		resp->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		resp->error = 0;
		resp->val = 0;
		if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) {
			perror("ioctl send");
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
	if (!cookie_valid(listener, req)) {
		fprintf(stderr, "task died before we could map its memory\n");
		goto out;
	}

	/*
	 * Phew, we've got the right /proc/pid/mem. Now we can read it. Note
	 * that to avoid another TOCTOU, we should read all of the pointer args
	 * before we decide to allow the syscall.
	 */

	// the arguments are shifted one to the right for all syscalls but open
	const int argoffset = nr != __NR_open;
	ret = pread(mem, pathname, sizeof(pathname), req->data.args[argoffset]);
	if (ret < 0) {
		perror("pread");
		goto out;
	}
	// Get the redirected file path
	if (!find_match(&proxy_pathname, pathname)) {
		// continue the syscall normally
		resp->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		resp->error = 0;
		resp->val = 0;
		if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) {
			ret = -1;
			perror("ioctl send");
		}
		goto out;
	}

	if (nr == __NR_openat2) {
		// read the special how struct
		ret = pread(mem, &how, sizeof(how), req->data.args[2]);
		if (ret < 0) {
			perror("pread");
			goto out;
		}
	}

	if (nr != __NR_open) {
		dirfd = ls_int(req->data.args[0]);
	}
	// Pass-through dirfd from supervised process, in case it is needed for openat.
	// This is the case if:
	// - pathname is not absolute
	// - dirfd is NOT AT_FDCWD
	//
	// For more info see man openat(2)
	if (dirfd >= 0 && pathname[0] != '/') {
		// duplicate the file descriptor
		ret = pidfd_getfd(pidfd, dirfd, 0);
		if (ret < 0) {
			perror("pidfd_getfd");
			goto out;
		} else {
			printf("Duplicating relative openat dirfd %d...", dirfd);
			proxy_dirfd = ret;
		}
	}

	if (!cookie_valid(listener, req)) {
		perror("post-read TOCTOU");
		goto out;
	}

	flags = ls_int(req->data.args[argoffset + 1]);
	mode = (mode_t) ls_int(req->data.args[argoffset + 2]);

	// Make the final system call
	// This will resolve to our overloaded syscall
	if (nr == __NR_open) {
		ret = open(proxy_pathname, flags, mode);
	} else if (nr == __NR_openat) {
		ret = openat(proxy_dirfd, proxy_pathname, flags, mode);
	} else if (nr == __NR_openat2) {
		ret = openat2(proxy_dirfd, proxy_pathname, &how, sizeof(struct open_how));
	}

	if (ret == -1) {
		ret = 0;
		// task got a signal and restarted the syscall
		if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT) {
			perror("ioctl send");
			goto out;
		}
	} else {
		// inject the file descriptor into the target process
		struct seccomp_notif_addfd addfd = {};
		addfd.id = req->id;
		addfd.flags = SECCOMP_ADDFD_FLAG_SEND; // add the fd and return it, atomically
		addfd.srcfd = ret;
		// note that this branch does not need the SECCOMP_IOCTL_NOTIF_SEND, because this ADDFD call already includes it due to the SECCOMP_ADDFD_FLAG_SEND flag
		ret = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
		if (ret == -1) {
			perror("SECCOMP_IOCTL_NOTIF_ADDFD");
			goto out;
		}
		resp->error = 0;
		// we need to close the fd on our side, it will still be open on the target side, since we already sent it above
		close(addfd.srcfd);
	}
out:
	if (proxy_dirfd >= 0) {
		close(proxy_dirfd);
	}
	close(mem);
	return ret;
}
