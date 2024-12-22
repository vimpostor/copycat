#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/openat2.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EXPECT(cond) if (!(cond)) { fprintf(stderr, "Failed assert: %s\n", #cond); exit(EXIT_FAILURE); }

void check_correct_fd(int fd) {
	EXPECT(fd >= 0);
	static char c;

	// we should be able to read from the file descriptor
	ssize_t r = read(fd, &c, 1);
	EXPECT(r);

	// the read char should be either 'a' or 'b' or 'c', depending on whether system calls are intercepted and which file is read
	EXPECT((c == 'a') || (c == 'b') || (c == 'c'));

	// close the descriptor again
	int a = close(fd);
	EXPECT(!a);
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
	size_t n = 100000;
	struct timespec start, end;

	// hot path, every call is intercepted and changed
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (size_t i = 0; i < n; ++i) {
		f = do_openat(hot_filename);
		check_correct_fd(f);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("openat (intercepted and modified): %lu.%lu s\n", end.tv_sec - start.tv_sec, end.tv_nsec - start.tv_nsec);

	// cold path, every call is intercepted but no arguments are changed (the BPF filter does not trigger)
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (size_t i = 0; i < n; ++i) {
		f = do_openat(cold_filename);
		check_correct_fd(f);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("openat (intercepted and not modified): %lu.%lu s\n", end.tv_sec - start.tv_sec, end.tv_nsec - start.tv_nsec);

	// passive path, no call is intercepted (no system calls)
	int primes = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	for (int i = 2; i < n; ++i) {
		primes += is_prime(i);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	printf("path with no system calls: Found %d primes in %lu.%lu s\n", primes, end.tv_sec - start.tv_sec, end.tv_nsec - start.tv_nsec);

	return EXIT_SUCCESS;
}
