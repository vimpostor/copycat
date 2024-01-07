#include "openat.h"

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
	const char *final_path = find_match(pathname);
	return original_calls.openat(dirfd, final_path, flags, mode);
}
