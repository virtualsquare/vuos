#ifndef VU_FD_TABLE_H
#define VU_FD_TABLE_H
#include <sys/stat.h>

struct vu_fnode_t;
struct vuht_entry_t;

void vu_fd_set_fnode(int fd, int nested, struct vu_fnode_t *fnode, int fdflags);

int vu_fd_close(int fd, int nested);

void vu_fd_dup(int fd, int nested, int oldfd, int fdflags);

struct vu_fnode_t *vu_fd_get_fnode(int fd, int nested);

struct vuht_entry_t *vu_fd_get_ht(int fd, int nested);

void vu_fd_get_path(int fd, int nested, char *dest,  size_t n);

mode_t vu_fd_get_mode(int fd, int nested);

int vu_fd_get_fdflags(int fd, int nested);

void vu_fd_set_fdflags(int fd, int nested, int flags);

int vu_fd_get_flflags(int fd, int nested);

void vu_fd_set_flflags(int fd, int nested, int flags);

int vu_fd_get_sfd(int fd, void **pprivate, int nested);

#endif
