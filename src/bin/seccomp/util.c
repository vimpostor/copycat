#include "util.h"

int ls_int(unsigned long long val) {
	return (int) val & 0x0f;
}
