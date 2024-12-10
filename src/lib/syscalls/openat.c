#include "openat.h"

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	return original_calls.openat(dirfd, pathname, flags, mode);
}
