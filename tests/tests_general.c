#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

void check_correct_fd(const int fd) {
	static char c;
	// we should be able to read from the file descriptor
	assert(read(fd, &c, 1));
	// the read char should be 'b', and not 'a'
	assert(c != 'a');
	assert(c == 'b');
}

int do_open(const char *filename) {
	return open(filename, O_RDONLY);
}

int main(int argc, char *argv[])
{
	const char filename[] = "/tmp/a";
	int f = -1;

	// open()
	f = do_open(filename);
	check_correct_fd(f);

	printf("All tests passed!\n");
	return 0;
}
