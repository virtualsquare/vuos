#ifndef _FUSENODE_H
#define _FUSENODE_H

#include <stdint.h>
#include <linux/fuse.h>

struct fusenode_buf;

uint64_t fn_get(struct fusenode_buf *ht,
		const char *path, struct fuse_attr *attr);

void fn_add(struct fusenode_buf *ht,
		const char *path, struct fuse_entry_out *entry);

uint64_t fn_getnode(struct fusenode_buf *ht,
		uint64_t nodeid,  struct fuse_attr *attr);

void fn_updatenode(struct fusenode_buf *ht,
		uint64_t nodeid,  struct fuse_attr_out *entry);

uint64_t fn_delnode(struct fusenode_buf *ht,
		uint64_t nodeid, uint64_t *nlookup);

uint64_t fn_forgetlru(struct fusenode_buf *ht, uint64_t *nlookup);

struct fusenode_buf *fn_init(int maxlru);

void fn_fini(struct fusenode_buf *ht);

#endif
