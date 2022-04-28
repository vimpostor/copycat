/**
 * Please see the header file for additional license information about this particular file.
 */
#include "seccomp_trap.h"

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}

int send_fd(int sock, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(cmsg)) = fd;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}

	return 0;
}

int recv_fd(int sock)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0) {
		perror("recvmsg");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	return *((int *)CMSG_DATA(cmsg));
}

int user_trap_syscall(int nr, unsigned int flags)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	return seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
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

	resp->id = req->id;
	resp->error = -EPERM;
	resp->val = 0;

	if (req->data.nr != __NR_openat) {
		fprintf(stderr, "huh? trapped something besides openat? %d\n", req->data.nr);
		return -1;
	}

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
	dirfd = (int) req->data.args[0] & 0x0f;

	if (lseek(mem, req->data.args[1], SEEK_SET) < 0) {
		perror("seek");
		goto out;
	}
	ret = read(mem, pathname, sizeof(pathname));
	if (ret < 0) {
		perror("read");
		goto out;
	}

	flags = (int) req->data.args[2] & 0x0f;

	mode = (mode_t) req->data.args[3] & 0x0f;

	if (0) {
		// TODO: Continue the syscall normally if nothing matches
		resp->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	}

	// this will resolve to our overloaded openat
	ret = openat(dirfd, pathname, flags, mode);
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
