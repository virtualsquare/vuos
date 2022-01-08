#ifndef _VUDEVFUSE_H
#define _VUDEVFUSE_H
#include <stdint.h>
#include <pthread.h>
#include <linux/fuse.h>
#include <vumodule.h>
#include <fusereqq.h>
#include <fusenode.h>

#define VUDEVFUSE_MODULE_FLAGS (VU_USE_PRW)
#define FUSENODE_BUFSIZE 256

extern struct vuht_entry_t *devfuse_ht;

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

struct fusemount_t {
	struct vuht_entry_t *ht;
	pthread_mutex_t mutex;
	int sem; //  < 0 if fd is closed
	unsigned long mountflags;
	mode_t rootmode; // unsupported
	uid_t uid;
	uid_t gid;
	uint64_t last_unique;
	struct fuse_init_out initdata;
	struct fusereq *reqq;
	struct fusereq *replyq;
	struct fusenode_buf *fnbuf;
	// mountflags
};

#endif
