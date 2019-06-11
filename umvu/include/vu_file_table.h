#ifndef VU_FILE_TABLE_H
#define VU_FILE_TABLE_H
#include<stdio.h>
#include<sys/stat.h>

/* This if the table of open files.
 *
 * NB there are three layers of data structures:
 *         fd_table, file_table (this, whose elements are named fnodes), vnode.
 * more elements of fd_table may point to the same fnode, several fnodes to the same vnode.
 *
 * dup/inherited file descriptors from fd_table point the same fnode element.
 *
 * fnodes point to the same vnode element if they refer to the same file.
 *
 * This module perform locking to support multithreading access
 */

struct vuht_entry_t;
struct vu_fnode_t;

/* set the "close" upcall. (one for each file type (see umvu/include/xstat.h) */
typedef int (* close_upcall_t)(struct vuht_entry_t *ht, int sfd, void *private);
void vu_fnode_set_close_upcall(mode_t mode, close_upcall_t close_upcall);

/* create an f-node:
 *  sfd is the service fd, the file descriptor used by the module to identify the file
 */
struct vu_fnode_t *vu_fnode_create(
		struct vuht_entry_t *ht,
		const char *path,
		struct stat *stat,
		int flags,
		int sfd,
		void *private);

/* close an fnode: delete the fnodeis the usage counter becomes 0 */
int vu_fnode_close(struct vu_fnode_t *fnode);

/* increment the usage count */
void vu_fnode_dup(struct vu_fnode_t *v);

/* helper functions */

struct vuht_entry_t *vu_fnode_get_ht(struct vu_fnode_t *v);

void vu_fnode_get_path(struct vu_fnode_t *v, char *dest,  size_t n);

char *vu_fnode_get_vpath(struct vu_fnode_t *v);

mode_t vu_fnode_get_mode(struct vu_fnode_t *v);

int vu_fnode_get_flags(struct vu_fnode_t *v);

void vu_fnode_set_flags(struct vu_fnode_t *v, int flags);

int vu_fnode_get_sfd(struct vu_fnode_t *v, void **pprivate);

/* a local copy of the file is required. copyinout calls the callback in 'cp'
	 with the right arguments and opportune locking */
typedef int (*copyfun) (struct vuht_entry_t *ht, char *path, char *tmp_path);
int vu_fnode_copyinout (struct vu_fnode_t *v, copyfun cp);

/* trunc of the local copy */
void vu_fnode_setminsize(struct vu_fnode_t *v, off_t length);

#endif
