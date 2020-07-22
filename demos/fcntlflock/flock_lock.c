#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <errno.h>

#define LI_MAX_SIZE 10

struct lock_info {
	int fd;
	int fd_o_mode;
	char* path;
	int operation;
};

struct lock_info opened_locks[LI_MAX_SIZE];

int get_first_free_lockinfo_index() {
	int i;

	for (i = 0; i < LI_MAX_SIZE
			&& opened_locks[i].fd != 0; i++) ;

	return i < LI_MAX_SIZE ? i : -1;
}

void open_file(char* path, int mode) {
	int res = open(path, O_CREAT | mode, S_IRUSR | S_IWUSR);

	if (res < 0) {
		printf("Error while opening %s\n", path);
		return;
	}

	int i = get_first_free_lockinfo_index();
	if (i == -1) {
		printf("No space left\n");
		return;
	}

	opened_locks[i] = (struct lock_info) { .fd=res, .fd_o_mode=mode, .path=path, .operation=-1 };

	printf("Successfully opened file %s, fd: %d\n", path, res);
}

void deinit() {
	for (int i = 0; i < LI_MAX_SIZE
			&& opened_locks[i].path != NULL; i++) {
		unlink(opened_locks[i].path);
	}
}

void init() {
	for (int i = 0; i < LI_MAX_SIZE; i++) {
		opened_locks[i] = (struct lock_info) { .fd=0, .fd_o_mode=0, .path=NULL, .operation=-1 };
	}
}

char* getOpStrFromInt(int cmd) {
	int noblock = cmd & LOCK_NB;
	char *nbstr = noblock ? " | LOCK_NB" : "";
	char *opstr;

	switch (cmd & ~LOCK_NB) {
		case LOCK_SH:
			opstr = "LOCK_SH";
			break;
		case LOCK_EX:
			opstr = "LOCK_EX";
			break;
		case LOCK_UN:
			opstr = "LOCK_UN";
			break;
		default:
			return "unknown";
	}

	char *res = malloc(sizeof(char));
	sprintf(res, "%s%s", opstr, nbstr);

	return res;
}

void apply_lock(int index) {
	int cmd;
	
	switch (index) {
		case 0:
			cmd = LOCK_SH;
			break;
		case 1:
			// exclusive lock, non-blocking
			cmd = LOCK_EX | LOCK_NB;
			break;
		case 2:
			cmd = LOCK_SH;
			break;
		case 3:
			opened_locks[index] = opened_locks[2];
			cmd = LOCK_SH;
			break;
		case 4:
			cmd = LOCK_EX | LOCK_NB;
		default:
			break;
	}

	// apply the lock
	int fd = opened_locks[index].fd;
	int res = flock(fd, cmd);
	if (res < 0) {
		int errnocpy = errno;
		printf("\n\t-------------------------------\n");
		printf("\t Cannot apply lock on index %d\n\t (fd %d, error: %d)\n",
				index, fd, errnocpy);
		printf("\t-------------------------------\n\n");
		return;
	}

	// save the lock in the global array
	struct lock_info* flinfo = &(opened_locks[index]);
	flinfo->operation = cmd;

	char *optstr = getOpStrFromInt(cmd); 
	printf("\n\t-------------------------------\n");
	printf("\t Lock applied to file %s, fd: %d\n", flinfo->path, flinfo->fd);
	printf("\t operation: %s\n", optstr);
	printf("\t-------------------------------\n\n");

	free(optstr);
}

void flush_stdin() {
	char c;

	while ((c = getchar()) != '\n' && c != EOF) ;
}

int main(int argc, char **argv) {
	init();

	open_file("/etc/passwd", O_RDONLY);
	open_file("/etc/shadow", O_WRONLY);
	open_file("/etc/hosts", O_RDWR);

	fgets(NULL, 0, stdin);
	flush_stdin();	// flush the stream to delete all unmatched characters
	apply_lock(0);

	fgets(NULL, 0, stdin);
	flush_stdin();
	apply_lock(1);

	fgets(NULL, 0, stdin);
	flush_stdin();
	apply_lock(2);

	fgets(NULL, 0, stdin);
	flush_stdin();
	apply_lock(3);

	fgets(NULL, 0, stdin);
	flush_stdin();
	open_file("write.lock", O_RDONLY);
	apply_lock(4);

	fgets(NULL, 0, stdin);
	flush_stdin();

	deinit();
}

