#ifndef VU_VNODE_H
#define VU_VNODE_H

struct vu_node_t;
struct vuht_entry_t;

struct vu_vnode_t *vu_vnode_open(struct vuht_entry_t *ht, ino_t dev, ino_t inode);

void vu_vnode_close(struct vu_vnode_t *vnode);

char *vu_vnode_getvpath(struct vu_vnode_t *vnode);

typedef int (*copyfun) (struct vuht_entry_t *ht, char *path, char *tmp_path);

int vu_vnode_copyinout (struct vu_vnode_t *vnode, char *path, copyfun cp);

void vu_vnode_setminsize(struct vu_vnode_t *vnode, off_t length);

#endif
