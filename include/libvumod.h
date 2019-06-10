#ifndef VUMODLIB_H
#define VUMODLIB_H
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/epoll.h>
#include <sys/mount.h>

/* pseudo file mgmt */

#define PSEUDOFILE_LOAD_CONTENTS 1
#define PSEUDOFILE_STORE_CLOSE 2
#define PSEUDOFILE_LOAD_DIRENTS 3

/* upcall: this is the prototype upcall function registered by pseudofile_open,
tag == PSEUDOFILE_LOAD_CONTENTS: upload the contents f-writing the file f
(this happens at first read/write/lseek)
tag == PSEUDOFILE_STORE_CLOSE: store/use the contents (and free any dynamic memory
allocated for pseudoprivate). f can be NULL if the file has been never read or written.
tag == PSEUDOFILE_LOAD_DIRENTS: populate the dir for getdents using pseudofile_filldir.
(this appens at first getdents64)
*/
typedef int (* pseudo_upcall)(int tag, FILE *f, int openflags, void *pseudoprivate);

/* helper function: convert struct stat's st_mode to struct dirent's d_type */
int pseudofile_mode2type(mode_t mode);

/* helper function: use path to fill in the buf of bufsiz bytes for readlink.
	 it returns -1/EINVAL if path is NULL */
ssize_t pseudofile_readlink_fill(char *path, char *buf, size_t bufsiz);

/* add an entry to the dir for getdents */
int pseudofile_filldir(FILE *f, char *name, ino_t ino, char type);

/* open a pseudofile: pseudoprivate is an opaque arg forwarded to the upcall.
	 *private value must be stored and passed to all the other function here below.
	 (e.g. using the private arg of the module's open syscall implementation */
int pseudofile_open(pseudo_upcall upcall, void *pseudoprivate, int flags, void **private);

/* syscall implementation for pseudofiles. The signature of these function has been
	 designed to be a drop in replacement for your module's functions. e.g. in yourmodule_init:
	 struct vu_service_t *s = vu_mod_getservice();
	 vu_syscall_handler(s, close) = pseudofile_close; 
	 */
int pseudofile_close(int fd, void *private);

int pseudofile_read(int fd, void *buf, size_t count, void *private);

int pseudofile_write(int fd, const void *buf, size_t count, void *private);

int pseudofile_lseek(int fd, off_t offset, int whence, void *private);

int pseudofile_getdents64(int fd,  struct dirent64 *dirp, unsigned int count, void *private);

#endif
