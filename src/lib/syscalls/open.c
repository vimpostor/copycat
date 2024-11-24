#include "open.h"

int open(const char *pathname, int flags, mode_t mode) {
	const char *final_path = find_match(pathname);
	return original_calls.open(pathname, flags, mode);
}
