#ifndef VU_FD_TABLE_H
#define VU_FD_TABLE_H
#include <sys/stat.h>

/* This module keeps track of the file descriptors of the
 * corresponding user-thread (or the fd of the hypervisor itself if nested == 1).
 *
 * NB there are three layers of data structures:
 *         fd_table (this), file_table (whose elements are named fnodes), vnode.
 * more elements of fd_table may point to the same fnode, several fnodes to the same vnode.
 *
 * clone/fork/exec are automatically handled:
 * in case of fork/clone. if CLONE_FILES the mapping is shared, copied otherwise.
 * in case of exec. the CLOEXEC entries are deleted.
 *
 * This module perform locking to support multithreading access
 */

struct vu_fnode_t;
struct vuht_entry_t;

/* store the mapping between fd and fnode */
void vu_fd_set_fnode(int fd, int nested, struct vu_fnode_t *fnode, int fdflags);

/* delete the mapping about fd */
int vu_fd_close(int fd, int nested);

/* manage a dup, copy the mapping */
void vu_fd_dup(int fd, int nested, int oldfd, int fdflags);

/* helper functions to get/set specific info*/
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
