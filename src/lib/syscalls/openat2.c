#include "openat2.h"

long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size) {
	const char *final_path = find_match(pathname);
	return original_calls.openat2(dirfd, final_path, how, size);
}
