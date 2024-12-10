#include "open.h"

int open(const char *pathname, int flags, mode_t mode) {
	return original_calls.open(pathname, flags, mode);
}
