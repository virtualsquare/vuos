#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	int fd = open("/proc/locks", O_RDONLY);
	if (fd < 0) {
		printf("Error on open(2)\n");
		exit(fd);
	}

	int dupfd = fcntl(fd, F_DUPFD_CLOEXEC, 7);
	printf("F_DUPFD result: %d\n", dupfd);

	int fl = fcntl(dupfd, F_GETFL, 34);
	printf("F_GETFL result: %d\n", fl);

	struct f_owner_ex setown = { F_OWNER_PID, getpid() };
	struct f_owner_ex getown;

	fcntl(dupfd, F_SETOWN_EX, &setown);
	fcntl(dupfd, F_GETOWN_EX, &getown);

	printf("F_GETOWN_EX result: type %d (%d), pid %d (%d)\n",
			getown.type,
			setown.type,
			getown.pid,
			setown.pid);

	return 0;
}
