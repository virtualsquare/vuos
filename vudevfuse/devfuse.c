/*
 * vudevfuse: /dev/fuse - virtual fuse kernel support
 * Copyright 2022 Renzo Davoli
 *     Virtualsquare & University of Bologna
 *
 * devfuse.c: /dev/fuse I/O management
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <vumodule.h>

#include <vudevfuse.h>
#include <fusereqq.h>
#include <eventsem.h>
#include <fusenode.h>
#include <devfuse.h>

// #define DEBUG

static struct vu_stat devfuse_stat = {
	.st_mode = S_IFCHR | 0666,
	.st_nlink = 1
};

static uint64_t newunique(struct fusemount_t *fusemount) {
	fusemount->last_unique += FUSE_REQ_ID_STEP;
	return fusemount->last_unique;
}

static size_t iov_total_len(const struct iovec *iov, int iovcnt) {
	size_t tlen = 0;
	for (int i = 0; i < iovcnt; i++)
		tlen += iov[i].iov_len;
	return tlen;
}

int vu_devfuse_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	(void) flags;
	(void) sfd;
	(void) fdprivate;
	if (pathname[1] != 0)
		return errno = ENOENT, -1;
	printkdebug(U,"DEV LSTAT %s", pathname);
	*buf = devfuse_stat;
	return 0;
}

int vu_devfuse_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct fusemount_t *fusemount = calloc(1, sizeof(struct fusemount_t));
	(void) pathname;
	(void) flags;
	(void) mode; //XXX CK??
	if (fusemount == NULL)
		return errno = ENOMEM, -1;
	fusemount->ht = NULL;
	fusemount->uid = geteuid();
	fusemount->gid = getegid();
	fusemount->fnbuf = fn_init(FUSENODE_BUFSIZE);
	pthread_mutex_init(&(fusemount->mutex), NULL);
	fusemount->sem = sem_open(0);
	*fdprivate = fusemount;
	printkdebug(U,"DEV OPEN -> %p sem %d", fusemount, fusemount->sem);
	return 0;
}

void fusemount_free(struct fusemount_t *fusemount) {
	int delete;
	pthread_mutex_lock(&(fusemount->mutex));
	delete = fusemount->ht == NULL && fusemount->sem < 0;
	pthread_mutex_unlock(&(fusemount->mutex));
	if (delete) {
		fn_fini(fusemount->fnbuf);
		pthread_mutex_destroy(&(fusemount->mutex));
		free(fusemount);
	}
}

int vu_devfuse_close(int fd, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	printkdebug(U,"DEV CLOSE -> %p", fusemount);
	if (fusemount->sem >= 0)
		sem_close(fusemount->sem);
	fusemount->sem = -1;
	fusemount_free(fusemount);
	return 0;
}

int vu_devfuse_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	//printkdebug(U,"DEV EPOLL -> %d %d sem %d", op, event ? event->events : -1, fusemount->sem);
	int retval = epoll_ctl(epfd, op, fusemount->sem, event);
	return retval;
}

#ifdef DEBUG
static void dump(const char *title, const uint8_t *data, size_t bufsize, ssize_t len) {
	ssize_t line, i;
	/* out format:
		 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		 01234567890123456789012345678901234567890123456789012345678901234
	 */
	char hexbuf[48];
	char charbuf[17];
	printk("%s size %zd len %zd:\n", title, bufsize, len);
	if (bufsize > 0 && len > 0) {
		for (line = 0; line < len; line += 16) {
			for (i = 0; i < 16; i++) {
				ssize_t pos = line + i;
				if (pos < len) {
					sprintf(hexbuf + (3 * i), "%02x ", data[pos]);
					charbuf[i] = data[pos] >= ' ' && data[pos] <= '~' ? data[pos] : '.';
				} else {
					sprintf(hexbuf + (3 * i), "   ");
					charbuf[i] = ' ';
				}
			}
			charbuf[i] = 0;
			printk("  %s %s\n", hexbuf, charbuf);
		}
	}
}
#endif

static ssize_t vu_devfuse_read_init(int fd, void *buf, size_t count, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	sem_P(fusemount->sem);
	pthread_mutex_lock(&(fusemount->mutex));
	struct {
		struct fuse_in_header reqh;
		struct fuse_init_in init;
	} init = {
		.reqh.len = sizeof(init),
		.reqh.opcode = FUSE_INIT,
		.reqh.unique = newunique(fusemount),
		.reqh.nodeid = FUSE_ROOT_ID,
		.reqh.uid = fusemount->uid,
		.reqh.gid = fusemount->gid,
		.reqh.pid = vu_mod_gettid(),
		.init.major = FUSE_KERNEL_VERSION,
		.init.minor = FUSE_KERNEL_MINOR_VERSION,
	};
	pthread_mutex_unlock(&(fusemount->mutex));
	if (count < sizeof(init))
		return errno = EINVAL, -1;
#ifdef DEBUG
	dump("vu_devfuse_read init", buf, count, sizeof(init));
#endif
	memcpy(buf, &init, sizeof(init));
	printkdebug(U, "DEV READ INIT maj %d min %d flags %x",
			init.init.major, init.init.minor, init.init.flags);
	return sizeof(init);
}

static ssize_t vu_devfuse_write_init(int fd, const void *buf, size_t count, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	const struct fuse_out_header *outh = buf;
	size_t init_out_len = count - sizeof(*outh);
	// printk("vu_devfuse_write_init init_out_len %d %d\n", init_out_len, outh->error);
	if (init_out_len < 8)
		return errno = EINVAL, -1;
	if (init_out_len > sizeof(fusemount->initdata))
		init_out_len = sizeof(fusemount->initdata);
#ifdef DEBUG
	dump("vu_devfuse_write init", buf, count, count);
#endif
	pthread_mutex_lock(&(fusemount->mutex));
	memcpy(&fusemount->initdata, outh+1, init_out_len);
	printkdebug(U, "DEV WRITE INIT maj %d min %d flags %x",
			fusemount->initdata.major,
			fusemount->initdata.minor,
			fusemount->initdata.flags);
	pthread_mutex_unlock(&(fusemount->mutex));
	return count;
}

ssize_t vu_devfuse_read(int fd, void *buf, size_t count, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	printkdebug(U,"DEV READ %p -> %d", fusemount, count);
	if (fusemount->initdata.major == 0)
		return vu_devfuse_read_init(fd, buf, count, fdprivate);
	sem_P(fusemount->sem);

	// printk("sem ok\n");
	pthread_mutex_lock(&(fusemount->mutex));
	struct fusereq *req = fusereq_dequeue(&fusemount->reqq);
	// printk("read req %p\n", req);
	if (req == NULL) { // umount-> EOF on dev
		// the fuse library uses several threads (workers)
		// ENODEV must be returned to *all* the pending read reqs
		sem_V(fusemount->sem);
		pthread_mutex_unlock(&(fusemount->mutex));
		return errno = ENODEV, -1;
	}
	struct fuse_in_header *h = buf;
	*h = req->reqh;
	uint8_t *data = (void *) (h + 1);
	size_t datalen = count;
	if (h->len < datalen) datalen = h->len;
	datalen	-= sizeof(*h);
	for (int i = 0; i < req->reqcnt && datalen > 0; i++) {
		size_t len = req->reqiov[i].iov_len;
		if (datalen < len) len = datalen;
		memcpy(data, req->reqiov[i].iov_base, len);
		data += len;
		datalen -= len;
	}
	if (req->replycnt == FUSE_NOREPLY)
		sem_V(req->sem);
	else
		fusereq_enqueue(req, &fusemount->replyq);
	pthread_mutex_unlock(&(fusemount->mutex));
#ifdef DEBUG
	dump("vu_devfuse_read", buf, count, h->len);
#endif
	return h->len;
}

ssize_t vu_devfuse_write(int fd, const void *buf, size_t count, void *fdprivate) {
	(void) fd;
	struct fusemount_t *fusemount = fdprivate;
	printkdebug(U,"DEV WRITE %p -> %d", fusemount, count);
	if (fusemount->initdata.major == 0)
		return vu_devfuse_write_init(fd, buf, count, fdprivate);
	const struct fuse_out_header *h = buf;

#ifdef DEBUG
	dump("vu_devfuse_write", buf, count, count);
#endif
	pthread_mutex_lock(&(fusemount->mutex));
	struct fusereq *req = fusereq_outqueue(h->unique & ~FUSE_INT_REQ_BIT, &fusemount->replyq);
	// printk("write req %p\n", req);
	// check!= NULL
	req->error = h->error;
	if (h->error >= 0) {
		uint8_t *data = (void *) (h + 1);
		size_t datalen = count;
		if (h->len < datalen) datalen = h->len;
		datalen -= sizeof(*h);
		for (int i = 0; i < req->replycnt && datalen > 0; i++) {
			size_t len = req->replyiov[i].iov_len;
			if (datalen < len) len = datalen;
			memcpy(req->replyiov[i].iov_base, data, len);
			req->replydatalen = datalen;
			data += len;
			datalen -= len;
		}
	}
	sem_V(req->sem);
	pthread_mutex_unlock(&(fusemount->mutex));
	return count;
}

int32_t vu_devfuse_conversation(struct fusemount_t *fusemount,
		uint32_t opcode, uint64_t nodeid,
		struct iovec *reqiov, int reqcnt,
		struct iovec *replyiov, int replycnt,
		size_t *return_len) {
	struct fusereq req = {
		.sem = sem_open(0),
		.reqh.len = sizeof(struct fuse_in_header) + iov_total_len(reqiov, reqcnt),
		.reqh.opcode = opcode,
		.reqh.unique = newunique(fusemount),
		.reqh.nodeid = nodeid,
		.reqh.uid = fusemount->uid,
		.reqh.gid = fusemount->gid,
		.reqh.pid = vu_mod_gettid(),
		.reqiov = reqiov,
		.reqcnt = reqcnt,
		.replyiov = replyiov,
		.replycnt = replycnt
	};
	//printk("c0\n");
	pthread_mutex_lock(&(fusemount->mutex));
	fusereq_enqueue(&req, &fusemount->reqq);
	sem_V(fusemount->sem);
	pthread_mutex_unlock(&(fusemount->mutex));
	//printk("c1\n");
	sem_P(req.sem);
	sem_close(req.sem);
	//printk("c2\n");
	if (return_len != NULL)
		*return_len = req.replydatalen;
	return req.error;
}
