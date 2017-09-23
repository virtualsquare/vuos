#ifndef VU_MMAP_TABLE_H
#define VU_MMAP_TABLE_H
#include <sys/types.h>

struct fnode;
void vu_mmap_mmap(uintptr_t addr, size_t length, struct vu_fnode_t *fnode, off_t offset);
void vu_mmap_munmap(uintptr_t addr, size_t length);
void vu_mmap_mremap(uintptr_t addr, size_t length, uintptr_t newaddr, size_t newlength);

#endif
