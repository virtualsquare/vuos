#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
	int fd = open("/proc/self", O_RDONLY);
	int res = syscall(73, -23, LOCK_SH);

	printf("fd: %d, return value: %d\n", fd, res);

	return 0;
}
