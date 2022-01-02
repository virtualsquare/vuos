#ifndef _FUSEREQQ_H
#define _FUSEREQQ_H

#include <stddef.h>
#include <sys/uio.h>
#include <linux/fuse.h>

struct fusereq {
	struct fusereq *next;
	int sem;
	struct fuse_in_header reqh;
	uint32_t error;
	struct iovec *reqiov;
	int reqcnt;
	struct iovec *replyiov;
	int replycnt;
	size_t replydatalen;
};

void fusereq_enqueue(struct fusereq *req, struct fusereq **tail);
struct fusereq *fusereq_dequeue(struct fusereq **tail);
struct fusereq *fusereq_outqueue(uint64_t unique, struct fusereq **tail);

#endif
