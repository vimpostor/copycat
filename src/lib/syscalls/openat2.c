#include "openat2.h"

long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size) {
	return original_calls.openat2(dirfd, pathname, how, size);
}
