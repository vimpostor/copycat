#include "openat2.h"

long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size) {
	/**
	 * glibc currently does not wrap openat2
	 * Therefore we must manually implement it via syscall
	 */
	return syscall(SYS_openat2, dirfd, pathname, how, size);
}
