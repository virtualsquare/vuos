#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char **argv) {
	int fd = 999;

	if (argc > 1) {
		fd = open(*argv, O_RDWR);
	}

	struct flock lockinfo = { 9472, SEEK_SET, 0, 0 };
	int res = fcntl(fd, F_SETLK, &lockinfo);
	int error = errno;

	printf("result: %d", res);
	if (res < 0) {
		printf(", error: %d", error);
	}

	printf("\n");

	return res;
}
