#ifndef VU_VNODE_H
#define VU_VNODE_H

/* This if the table of vnodes.
 *
 * NB there are three layers of data structures:
 *         fd_table, file_table (whose elements are named fnodes), vnode (this).
 * more elements of fd_table may point to the same fnode, several fnodes to the same vnode.
 *
 * dup/inherited file descriptors from fd_table point the same fnode element.
 * fnodes point to the same vnode element if they refer to the same file.
 *
 * This module perform locking to support multithreading access
 */


struct vu_node_t;
struct vuht_entry_t;

/* open/close a vnode element ht+dev+inode together are the unique identifier
	 of a vnode, open creates a new element if that file has not been opened yet,
	 otherwise it returns the pointer to the corresponding vnode (and increment
	 the usage counter)
 */
struct vu_vnode_t *vu_vnode_open(struct vuht_entry_t *ht, ino_t dev, ino_t inode);
/* close decrements the usage counter, delete the local copy and free the vnode when
	 the counter becomes zero) */
void vu_vnode_close(struct vu_vnode_t *vnode);

/* this is the pathname of a real file, local "image" of a virtual file.
	 it is often an empty file used to open "something" in the user process to
	 alocate a file descriptor.
	 The original contents of the file is loaded to support mmap or execve */
char *vu_vnode_getvpath(struct vu_vnode_t *vnode);

typedef int (*copyfun) (struct vuht_entry_t *ht, char *path, char *tmp_path);

int vu_vnode_copyinout (struct vu_vnode_t *vnode, char *path, copyfun cp);

void vu_vnode_setminsize(struct vu_vnode_t *vnode, off_t length);

#endif
