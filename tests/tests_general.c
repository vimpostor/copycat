#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

void check_correct_fd(int fd) {
	static char c;
	// we should be able to read from the file descriptor
	assert(read(fd, &c, 1));
	// the read char should be 'b', and not 'a'
	assert(c != 'a');
	assert(c == 'b');

	// close the descriptor again
	assert(!close(fd));
}

int do_open(const char *filename) {
	return open(filename, O_RDONLY);
}

int do_openat(const char *filename) {
	return openat(0, filename, O_RDONLY);
}

int do_openat2(const char *filename) {
	struct open_how how = {O_RDONLY, 0, 0};
	return syscall(SYS_openat2, 0, filename, &how, sizeof(struct open_how));
}

int main(int argc, char *argv[])
{
	const char filename[] = "/tmp/a";
	int f = -1;

	// open()
	f = do_open(filename);
	check_correct_fd(f);

	// openat()
	f = do_openat(filename);
	check_correct_fd(f);

	// openat2()
	f = do_openat2(filename);
	check_correct_fd(f);

	printf("All tests passed!\n");
	return EXIT_SUCCESS;
}
