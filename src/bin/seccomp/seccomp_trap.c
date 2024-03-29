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

int user_trap_syscall(int nr, unsigned int flags)
{
	struct sock_filter filter[] = {
		// Check that architecture matches
		// https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html#pitfalls
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 0, 2),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, X32_SYSCALL_BIT, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
		// decide wheter to allow the syscall
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

int user_trap_syscalls(const int *nrs, size_t length, unsigned int flags) {
	// we need 5 initial check instruction, length many JMP instructions and 2 final RET instructions
	const int init_length = 5;
	const int end_length = 2;
	const int bpf_length = MIN(init_length + length + end_length, MAX_FILTER_SIZE);

	struct sock_filter filter[MAX_FILTER_SIZE];

	// load arch
	filter[0].code = (unsigned short) BPF_LD+BPF_W+BPF_ABS;
	filter[0].jt = 0;
	filter[0].jf = 0;
	filter[0].k = offsetof(struct seccomp_data, arch);

	// check arch
	filter[1].code = (unsigned short) BPF_JMP+BPF_JEQ+BPF_K;
	filter[1].jt = 0;
	filter[1].jf = 2;
	filter[1].k = AUDIT_ARCH_X86_64;

	// load the number of the current syscall
	filter[2].code = (unsigned short) BPF_LD+BPF_W+BPF_ABS;
	filter[2].jt = 0;
	filter[2].jf = 0;
	filter[2].k = offsetof(struct seccomp_data, nr);

	// for the x32 ABI, all system call numbers have bit 30 set
	filter[3].code = (unsigned short) BPF_JMP+BPF_JGE+BPF_K;
	filter[3].jt = 0;
	filter[3].jf = 1;
	filter[3].k = X32_SYSCALL_BIT;

	// terminate the process if one of the earlier checks jumped here
	filter[4].code = (unsigned short) BPF_RET+BPF_K;
	filter[4].jt = 0;
	filter[4].jf = 0;
	filter[4].k = SECCOMP_RET_KILL_PROCESS;

	// now with the syscall nr still loaded, dynamically add checks for all syscall nrs we want to intercept
	// Warning: If there are more nrs than MAX_FILTER_SIZE - 3, we may omit some system calls
	// But this is still more sane than writing out of bounds
	for (int i = 0; i < bpf_length - end_length - init_length; ++i) {
		const int filter_index = i + init_length;
		// jump if equal
		filter[filter_index].code = (unsigned short) BPF_JMP+BPF_JEQ+BPF_K;
		// if equal (found a matching syscall), jump to early SECCOMP_RET_USER_NOTIF return
		// the jump distance is the difference between the curent index and the last index (which has index len - 1), but again minus one, because BPF does one implicit jump forward on each instruction
		filter[filter_index].jt = (bpf_length - 1) - filter_index - 1;
		// if not equal (no matching syscall yet), try the next syscall nr in the next line (so don't jump at all)
		filter[filter_index].jf = 0;
		// match against the syscall nr
		filter[filter_index].k = nrs[i];
	}

	// didn't find a matching syscall, so return allow
	filter[bpf_length - 2].code = (unsigned short) BPF_RET+BPF_K;
	filter[bpf_length - 2].jt = 0;
	filter[bpf_length - 2].jf = 0;
	filter[bpf_length - 2].k = SECCOMP_RET_ALLOW;

	// this is the jump target. If we found a matching syscall, we return SECCOMP_RET_USER_NOTIF
	filter[bpf_length - 1].code = (unsigned short) BPF_RET+BPF_K;
	filter[bpf_length - 1].jt = 0;
	filter[bpf_length - 1].jf = 0;
	filter[bpf_length - 1].k = SECCOMP_RET_USER_NOTIF;

	struct sock_fprog prog = {
		.len = (unsigned short) bpf_length,
		.filter = filter,
	};

	return seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
}
