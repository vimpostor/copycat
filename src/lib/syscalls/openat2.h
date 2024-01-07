#pragma once

#include "copycat.h"

long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
