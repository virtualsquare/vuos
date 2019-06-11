#ifndef VU_FNODE_COPY_H
#define VU_FNODE_COPY_H

struct vu_fnode_t;
/* get a local copy or the filei corresponding to fnode */
int vu_fnode_copyin(struct vu_fnode_t *fnode);
/* use the local copy to update the file corresponding to fnode */
int vu_fnode_copyout(struct vu_fnode_t *fnode);

/* this functions use vu_fnode_copyinout */
#endif
