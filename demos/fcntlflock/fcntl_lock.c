#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define LI_MAX_SIZE 10

struct lock_info {
	int fd;
	int fd_o_mode;
	char* path;
	struct flock* lock_params;
};

struct lock_info opened_locks[LI_MAX_SIZE];

int get_first_free_lockinfo_index() {
	int i;

	for (i = 0; i < LI_MAX_SIZE
			&& opened_locks[i].fd != 0; i++) ;

	return i < LI_MAX_SIZE ? i : -1;
}

int push_to_locks_array(struct lock_info linfo) {
	int i = get_first_free_lockinfo_index();
	if (i == -1) {
		printf("No space left\n");
		return -1;
	}

	opened_locks[i] = linfo;
	return i;
}

int open_file(char* path, int mode) {
	int res = open(path, O_CREAT | mode, S_IRUSR | S_IWUSR);

	if (res < 0) {
		printf("Error while opening %s\n", path);
		return -1;
	}

	struct lock_info linfo = (struct lock_info) { .fd=res, .fd_o_mode=mode, .path=path, .lock_params=NULL };
	int index = push_to_locks_array(linfo);
	if (index != -1) {
		printf("Successfully opened file %s, fd: %d\n", path, res);
		return index;
	}

	return -2;
}

int duplicate(int atIndex) {
	int newfd = dup(opened_locks[atIndex].fd);

	if (newfd < 0) {
		printf("\ndup failed\n\n");
		return -1;
	}

	struct lock_info linfo = opened_locks[atIndex];
	linfo.fd = newfd;
	
	int index = push_to_locks_array(linfo);
	if (index != -1) {
		printf("Successfully dup'ed fd %d, the new one is %d\n", opened_locks[atIndex].fd, newfd);
		return index;
	}

	return -2;
}

void init() {
	for (int i = 0; i < LI_MAX_SIZE; i++) {
		opened_locks[i] = (struct lock_info) { .fd=0, .fd_o_mode=0, .path=NULL, .lock_params=NULL };
	}
}

void deinit() {
	for (int i = 0; i < LI_MAX_SIZE
			&& opened_locks[i].path != NULL
			&& opened_locks[i].lock_params != NULL; i++) {
		unlink(opened_locks[i].path);
		free(opened_locks[i].lock_params);
		opened_locks[i].lock_params = NULL;
	}
}

const char* getTypeStrFromInt(int type) {
	switch (type) {
		case F_RDLCK:
			return "F_RDLCK";
		case F_WRLCK:
			return "F_WRLCK";
		case F_UNLCK:
			return "F_UNLCK";
		default:
			return "unknown";
	}
}

void apply_lock(int index) {
	// malloc'ing this because it will be stored after the method returns
	struct flock* lockinfo = malloc(sizeof(struct flock));
	int cmd;
	
	switch (index) {
		case 0:
			*lockinfo = (struct flock) { F_RDLCK, SEEK_SET, 0, 0 };
			cmd = F_SETLK;
			break;
		case 1:
			*lockinfo = (struct flock) { F_WRLCK, SEEK_SET, 0, 0 };
			cmd = F_SETLK;
			break;
		case 2:
			*lockinfo = (struct flock) { F_RDLCK, SEEK_SET, 5, 7 };
			cmd = F_SETLK;
			break;
		case 3:
			opened_locks[index] = opened_locks[0];
			
			// avoid double-freeing this pointer if the fcntl call fails
			opened_locks[index].lock_params = NULL;	

			*lockinfo = (struct flock) { F_WRLCK, SEEK_SET, 2, 9 };
			cmd = F_SETLK;
			break;
		case 4:
			*lockinfo = (struct flock) { F_UNLCK, SEEK_SET, 0, 0 };
			cmd = F_SETLK;
			break;
		default:
			break;
	}

	// apply the lock
	int res = fcntl(opened_locks[index].fd, cmd, lockinfo);
	if (res < 0) {
		printf("\n\t-------------------------------\n");
		printf("\t Cannot apply lock on index %d\n", index);
		printf("\t-------------------------------\n\n");

		// pointer not stored anywhere so it must be free'd here
		free(lockinfo);
		return;
	}

	// save the lock in the global array
	struct lock_info* flinfo = &(opened_locks[index]);
	flinfo->lock_params = lockinfo;

	printf("\n\t-------------------------------\n");
	printf("\t Lock applied to file %s, fd: %d\n", flinfo->path, flinfo->fd);
	printf("\t l_type: %s\n", getTypeStrFromInt(lockinfo->l_type));
	printf("\t l_whence: %s\n", lockinfo->l_whence == SEEK_SET ? "SEEK_SET" : "SEEK_END or SEEK_CUR");
	printf("\t l_start: %d\n", lockinfo->l_start);
	printf("\t l_len: %d\n", lockinfo->l_len);
	printf("\t-------------------------------\n\n");
}

void populate_file(int fd) {
	char* text = "this is the file content\n";
	
	size_t writtenb = write(fd, text, 100);
	printf("%d bytes written to fd %d\n", writtenb, fd);
}

void flush_stdin() {
	char c;

	// consume all characters in stdin
	// not doing so will cause stdin unread characters to be read
	// from the next fgets call, that will immediately return
	while ((c = getchar()) != '\n' && c != EOF) ;
}

int main(int argc, char **argv) {
	init();

	/*
	char *FILE1 = "read.lock";
	char *FILE2 = "write.lock";
	char *FILE3 = "partial_read.lock";
	*/

	char *FILE1 = "/etc/passwd";
	char *FILE2 = "/etc/shadow";
	char *FILE3 = "/etc/passwd";

	open_file(FILE1, O_RDONLY);
	open_file(FILE2, O_WRONLY);
	open_file(FILE3, O_RDWR);

	// write something into the file that will be partially locked
	//populate_file(opened_locks[2].fd);

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
	// get another fd for the same file
	int index = open_file(FILE2, O_RDWR);
	// closig this fd will cause the release of all the opened locks
	// even if it wasn't used to acquire any lock
	close(opened_locks[index].fd);
	printf("fd %d closed\n", opened_locks[index].fd);

	fgets(NULL, 0, stdin);
	flush_stdin();
	// get a dup'ed fd for the element at the specified index
	int dupindex = duplicate(0);
	// closing this fd will cause the release of all the locks onto the
	// file the original fd referred to
	close(opened_locks[dupindex].fd);
	printf("fd %d closed\n", opened_locks[dupindex].fd);

	fgets(NULL, 0, stdin);
	flush_stdin();
	deinit();
}
