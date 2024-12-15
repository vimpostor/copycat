#include "openat.h"

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	return syscall(SYS_openat, dirfd, pathname, flags, mode);
}
