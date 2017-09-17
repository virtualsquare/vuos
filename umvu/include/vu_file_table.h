#ifndef VU_FILE_TABLE_H
#define VU_FILE_TABLE_H
#include<stdio.h>
#include<sys/stat.h>

struct hashtable_obj_t;
struct vu_fnode_t;

typedef int (* close_upcall_t)(struct hashtable_obj_t *ht, int sfd, void *private);
void vu_fnode_set_close_upcall(close_upcall_t close_upcall);

struct vu_fnode_t *vu_fnode_create(
		struct hashtable_obj_t *ht,
		const char *path,
		struct stat *stat,
		int flags,
		int sfd,
		void *private);

int vu_fnode_close(struct vu_fnode_t *fnode);

void vu_fnode_dup(struct vu_fnode_t *v);

struct hashtable_obj_t *vu_fnode_get_ht(struct vu_fnode_t *v);

void vu_fnode_get_path(struct vu_fnode_t *v, char *dest,  size_t n);

char *vu_fnode_get_vpath(struct vu_fnode_t *v);

mode_t vu_fnode_get_mode(struct vu_fnode_t *v);

int vu_fnode_get_flags(struct vu_fnode_t *v);

void vu_fnode_set_flags(struct vu_fnode_t *v, int flags);

int vu_fnode_get_sfd(struct vu_fnode_t *v, void **pprivate);

#endif
