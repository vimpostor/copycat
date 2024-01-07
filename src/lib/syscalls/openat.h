#pragma once

#include "copycat.h"

int openat(int dirfd, const char *pathname, int flags, mode_t mode);
