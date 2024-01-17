#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

void check_correct_fd(int fd) {
	assert(fd >= 0);
	static char c;

	// we should be able to read from the file descriptor
	ssize_t r = read(fd, &c, 1);
	assert(r);

	// the read char should be either 'a' or 'b' or 'c', depending on whether system calls are intercepted and which file is read
	assert((c == 'a') || (c == 'b') || (c == 'c'));

	// close the descriptor again
	int a = close(fd);
	assert(!a);
}

int do_openat(const char *filename) {
	return openat(0, filename, O_RDONLY);
}

// we need to do a benchmark without system calls involved, to check for general performance overhead
int is_prime(int n) {
	for (int i = 2; i <= sqrt(n); ++i) {
		if ((n % i) == 0) {
			return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	const char hot_filename[] = "/tmp/a";
	const char cold_filename[] = "/tmp/c";
	int f = -1;
	size_t n = 1000;
	struct timespec start, end;

	// hot path, every call is intercepted and changed
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (size_t i = 0; i < n; ++i) {
		f = do_openat(hot_filename);
		check_correct_fd(f);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("openat (intercepted and modified): %lu us\n", (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000);

	// cold path, every call is intercepted but no arguments are changed (the BPF filter does not trigger)
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (size_t i = 0; i < n; ++i) {
		f = do_openat(cold_filename);
		check_correct_fd(f);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("openat (intercepted and not modified): %lu us\n", (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000);

	// passive path, no call is intercepted (no system calls)
	int primes = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (int i = 2; i < n; ++i) {
		primes += is_prime(i);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("path with no system calls: Found %d primes in %lu us\n", primes, (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000);

	return EXIT_SUCCESS;
}
