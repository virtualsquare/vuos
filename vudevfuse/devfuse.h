#ifndef _DEVFUSE_H
#define _DEVFUSE_H

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#define FUSE_INT_REQ_BIT (1ULL << 0)
#define FUSE_REQ_ID_STEP (1ULL << 1)

#define FUSE_NOREPLY (-1)

int vu_devfuse_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate);
int vu_devfuse_open(const char *pathname, int flags, mode_t mode, void **fdprivate);
int vu_devfuse_close(int fd, void *fdprivate);
int vu_devfuse_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate);
ssize_t vu_devfuse_read(int fd, void *buf, size_t count, void *fdprivate);
ssize_t vu_devfuse_write(int fd, const void *buf, size_t count, void *fdprivate);
#define vu_devfuse_nosys(...) (errno = ENOSYS, -1)


int32_t vu_devfuse_conversation(struct fusemount_t *fusemount,
		uint32_t opcode, uint64_t nodeid,
		struct iovec *reqiov, int reqcnt,
		struct iovec *replyiov, int replycnt,
		size_t *return_len);

void fusemount_free(struct fusemount_t *fusemount);

#define IOV0	NULL, 0
#define IOV_NOREPLY	NULL, FUSE_NOREPLY
#define IOV1(BASE, LEN)	(struct iovec []) {{(void *) (BASE), (LEN)}}, 1
#define IOV2(BASE0, LEN0, BASE1, LEN1)	\
	(struct iovec []) {{(void *) (BASE0), (LEN0)}, {(void *) (BASE1), (LEN1)}}, 2
#define IOV3(BASE0, LEN0, BASE1, LEN1, BASE2, LEN2)	\
	(struct iovec []) { \
		{(void *) (BASE0), (LEN0)}, \
		{(void *) (BASE1), (LEN1)}, \
		{(void *) (BASE2), (LEN2)}}, 3

#endif
