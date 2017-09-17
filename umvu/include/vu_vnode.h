#ifndef VU_VNODE_H
#define VU_VNODE_H

struct vu_node_t;

struct vu_vnode_t *vu_vnode_open(ino_t dev, ino_t inode);

void vu_vnode_close(struct vu_vnode_t *vnode);

char *vu_vnode_getvpath(struct vu_vnode_t *vnode);

#endif
