/**
 * This file (seccomp_trap) is directly based on "samples/seccomp/user-trap.c" from the Linux kernel source tree.
 * The source code can be retreived at git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
 * The Linux kernel is licensed under the GPLv2 license, which is compatible with the GPLv3 license of this project.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int seccomp(unsigned int op, unsigned int flags, void *args);
int send_fd(int sock, int fd);
int recv_fd(int sock);
int user_trap_syscall(int nr, unsigned int flags);
int handle_req(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int listener);
