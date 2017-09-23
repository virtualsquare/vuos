#ifndef VU_FNODE_COPY_H
#define VU_FNODE_COPY_H
struct vu_fnode_t;
int vu_fnode_copyin(struct vu_fnode_t *fnode);
int vu_fnode_copyout(struct vu_fnode_t *fnode);
#endif
