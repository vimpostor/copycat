#include "seccomp_trap.h"

#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <linux/seccomp.h>

// the maximum size of the BPF filter code
#define MAX_FILTER_SIZE 16
#define X32_SYSCALL_BIT 0x40000000

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

int user_trap_syscalls(const int *nrs, size_t length, unsigned int flags) {
	struct sock_filter filter[MAX_FILTER_SIZE];
	int i = 0;

	// load arch
	filter[i++] = (struct sock_filter) BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch));

	// check arch
	filter[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 0, 2);

	// load the number of the current syscall
	filter[i++] = (struct sock_filter) BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr));

	// for the x32 ABI, all system call numbers have bit 30 set
	filter[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, X32_SYSCALL_BIT, 0, 1);

	// terminate the process if one of the earlier checks jumped here
	filter[i++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS);

	// now with the syscall nr still loaded, dynamically add checks for all syscall nrs we want to intercept
	for (int j = 0; j < length; ++j) {
		// jump if equal
		filter[i].code = (unsigned short) BPF_JMP+BPF_JEQ+BPF_K;
		// if equal (found a matching syscall), jump to early SECCOMP_RET_USER_NOTIF return
		// the jump distance is the difference between the current index and the last index of this for loop series (which has index len - 1), plus two to jump from the last index inside the for loop to the actual intended location, but again minus one, because BPF does one implicit jump forward on each instruction
		filter[i].jt = (length - 1) - j + 2 - 1;
		// if not equal (no matching syscall yet), try the next syscall nr in the next line (so don't jump at all)
		filter[i].jf = 0;
		// match against the syscall nr
		filter[i++].k = nrs[j];
	}

	// didn't find a matching syscall, so return allow
	filter[i++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW);

	// this is the jump target. If we found a matching syscall, we return SECCOMP_RET_USER_NOTIF
	filter[i++] = (struct sock_filter) BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF);

	struct sock_fprog prog = {
		// i points to the next (still unused) index, so it is equal to the actual length
		.len = (unsigned short) i,
		.filter = filter,
	};
	return seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
}
