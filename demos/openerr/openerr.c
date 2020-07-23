#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv) {
	const char path[] = "non-existent-file";
	int fd = open(path, O_RDONLY);
	return fd;
}

