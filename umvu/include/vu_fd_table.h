#ifndef VU_FD_TABLE_H
#define VU_FD_TABLE_H
#include <sys/stat.h>


struct fnode_t;
struct vuht_entry_t;

/**vu_fnode_t structures are kept in a table and are associated with a file descriptor.
	fd is associated to fnode without checking if there was a previous association for that fd.*/
void vu_fd_set_fnode(int fd, int nested, struct fnode_t *fnode, int fdflags);

int vu_fd_close(int fd, int nested);

void vu_fd_dup(int fd, int nested, int oldfd, int fdflags);

struct fnode_t *vu_fd_get_fnode(int fd, int nested);

struct vuht_entry_t *vu_fd_get_ht(int fd, int nested);

void vu_fd_get_path(int fd, int nested, char *dest,  size_t n);

mode_t vu_fd_get_mode(int fd, int nested);

int vu_fd_get_fdflags(int fd, int nested);

void vu_fd_set_fdflags(int fd, int nested, int flags);

int vu_fd_get_flflags(int fd, int nested);

void vu_fd_set_flflags(int fd, int nested, int flags);

/**The module works with/uses the service file desciptor.
	When we are invoking a service syscall that need a file descriptor as parameter, the sfd is provided to it instead of fd.
	sfd is generally the file descriptor returned by an open service syscall or by an epoll_create.*/
int vu_fd_get_sfd(int fd, void **pprivate, int nested);

#endif
