#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const char filename[] = "/tmp/a";
	char c;

	int f = open(filename, O_RDONLY);
	assert(read(f, &c, 1));
	assert(c == 'b');
	return 0;
}
