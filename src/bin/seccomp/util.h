#pragma once

/**
 * Returns the least significant 32 bit part of a 64 bit integer as int
 *
 * seccomp returns 64 bit integer arguments, but only the 32 lowest bits contain the actual value
 * the upper 32 bits should be zeroed out
 *
 * Read man 2 seccomp for more details
 */
int ls_int(unsigned long long val);
