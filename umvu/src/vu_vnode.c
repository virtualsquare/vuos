/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <pthread.h>

#include <linux_32_64.h>
#include <r_table.h>
#include <vu_log.h>
#include <vu_tmpdir.h>
#include <vu_vnode.h>

struct vu_vnode_t {
	pthread_mutex_t mutex;
	struct vuht_entry_t *ht;
	dev_t dev;
	ino_t inode;
	char *vpath;
	long usage_count;
	long flags;
	struct vu_vnode_t *next;
};

#define VU_VNODE_HASH_SIZE 256
#define VU_VNODE_HASH_MASK (VU_VNODE_HASH_SIZE - 1)

static pthread_mutex_t vnode_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct vu_vnode_t *vnode_hash[VU_VNODE_HASH_SIZE];

__attribute__((always_inline))
	static inline int vnode_hashfun(struct vuht_entry_t *ht, dev_t dev, ino_t inode)
{
	uintptr_t htint = (uintptr_t) ht;
	return (major(dev) + minor(dev) + inode + ((13 * htint) ^ (htint >> 13))) & VU_VNODE_HASH_MASK;
}

static struct vu_vnode_t **vnode_search(struct vuht_entry_t *ht, dev_t dev, ino_t inode) {
	struct vu_vnode_t **scan;
	for (scan = &vnode_hash[vnode_hashfun(ht, dev, inode)];
			*scan != NULL; scan = &((*scan) -> next)) {
		struct vu_vnode_t *this = *scan;
		if (this->ht == ht && this->dev == dev && this->inode == inode)
			break;
	}
	return scan;
}

struct vu_vnode_t *vu_vnode_open(struct vuht_entry_t *ht, ino_t dev, ino_t inode) {
	struct vu_vnode_t **vnode_ptr;

	pthread_mutex_lock(&vnode_mutex);
	vnode_ptr = vnode_search(ht, dev, inode);
	if (*vnode_ptr == NULL) {
		struct vu_vnode_t *new_vnode = malloc(sizeof(struct vu_vnode_t));
		fatal(new_vnode);
		pthread_mutex_init(&new_vnode->mutex, NULL);
		new_vnode->ht = ht;
		new_vnode->dev = dev;
		new_vnode->inode = inode;
		asprintf(&new_vnode->vpath, "%s/%p_%lx_%lx",
				vu_tmpdirpath(), (void *) ht,
				(unsigned long) dev, (unsigned long) inode);
		new_vnode->usage_count = 1;
		new_vnode->flags = 0;
		new_vnode->next = NULL;
		*vnode_ptr = new_vnode;
		printkdebug(v, "vnode open %s count 1 (new)", new_vnode->vpath);
	} else {
		struct vu_vnode_t *this = *vnode_ptr;
		this->usage_count++;
		printkdebug(v, "vnode open %s count %d", this->vpath, this->usage_count);
	};
	pthread_mutex_unlock(&vnode_mutex);
	return *vnode_ptr;
}

void vu_vnode_close(struct vu_vnode_t *vnode) {
	pthread_mutex_lock(&vnode_mutex);
	printkdebug(v, "vnode close %s count %d", vnode->vpath, vnode->usage_count);
	if (--vnode->usage_count == 0) {
		struct vu_vnode_t **vnode_ptr = vnode_search(vnode->ht, vnode->dev, vnode->inode);
		struct vu_vnode_t *this = *vnode_ptr;
		fatal(this);
		*vnode_ptr = this->next;
		if (this->vpath) {
			/* XXX update file if mmapped and dirty */
			pthread_mutex_destroy(&this->mutex);
			r_unlink(this->vpath);
			free(this->vpath);
		}
		free(this);
	}
	pthread_mutex_unlock(&vnode_mutex);
}

/* no lock needed, usage count guarantees that there are no risks */
char *vu_vnode_getvpath(struct vu_vnode_t *vnode) {
	return vnode->vpath;
}

int vu_vnode_copyinout (struct vu_vnode_t *vnode, char *path, copyfun cp) {
	int ret_value;
	pthread_mutex_lock(&vnode->mutex);
	ret_value = cp(vnode->ht, path, vnode->vpath);
  pthread_mutex_unlock(&vnode->mutex);
	return ret_value;
}

void vu_vnode_setminsize(struct vu_vnode_t *vnode, off_t length) {
	struct vu_stat buf[1];
	pthread_mutex_lock(&vnode_mutex);
	r_vu_lstat(vnode->vpath, buf);
	if (length > buf->st_size)
		r_truncate(vnode->vpath, length);
	pthread_mutex_unlock(&vnode_mutex);
}

/* XXX flags field has been added for mmap support
	 when mmapped the file must be copied.
	 read and mmap will then take place on the fake file in the tmpdir.

	 a "dirty" bit can be used to support write ops on mmap.
	 if the file is dirty it will need to be copied back.

	 a rwlock seems to be neede to implement mmap.
	 during the file copy (to the tmp dir) any I/O operation on the file
	 need to be suspended */

__attribute__((constructor))
  static void init(void) {
    debug_set_name(v, "VNODE");
  }

