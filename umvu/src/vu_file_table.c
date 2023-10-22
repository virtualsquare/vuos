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
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <vu_log.h>
#include <xcommon.h>
#include <xstat.h>
#include <vu_vnode.h>
#include <vu_file_table.h>

#define UPDATABLE_FLAGS (O_APPEND | O_ASYNC | O_DIRECT | O_NOATIME | O_NONBLOCK)

/* file table element */
struct vu_fnode_t {
	pthread_rwlock_t lock;
	struct vuht_entry_t *ht;  // ht entry of the module (NULL if the file is not virtualized)
	char *path;               // absolute, canonicalized path of the file
	struct vu_vnode_t *vnode; // pointer to the vnode
	mode_t mode;              // mode (including file type)
	int flags;                // flags
	int count;                // number of fd table entries sharing this element
	off_t pos;                // file position for VU_USE_PRW
	/* module/service fields */
	/* the values returned by the modules' implementations of open/socket/accept may not be real
		 file descriptors. These values are just integers meaningful for the module itself:
		 "service file descriptors", or sfd */
	int sfd;                  // file descritor as known by the module
	void *private;            // Private data for modules
};

static int null_close_upcall(struct vuht_entry_t *ht, int sfd, void *private);
static close_upcall_t vu_fnode_close_upcall[S_TYPES] = {S_TYPES_INIT(null_close_upcall)};

void vu_fnode_set_close_upcall(mode_t mode, close_upcall_t close_upcall) {
	vu_fnode_close_upcall[S_MODE2TYPE(mode)] = close_upcall;
}

struct vu_fnode_t *vu_fnode_create(
		struct vuht_entry_t *ht,
		const char *path,
		struct vu_stat *stat,
		int flags,
		int sfd,
		void *private) {
	struct vu_fnode_t *fnode = malloc(sizeof(struct vu_fnode_t));
	fatal(fnode);
	fnode->ht = ht;
	fnode->path = xstrdup(path);
	if (stat != NULL) {
		fnode->vnode = vu_vnode_open(ht, stat->st_dev, stat->st_ino, stat->st_size,
				!!(flags & O_TRUNC));
		fnode->mode = stat->st_mode;
	} else {
		fnode->vnode = NULL;
		fnode->mode = 0;
	}
	fnode->flags = flags;
	fnode->count = 1;
	fnode->pos = 0;
	fnode->sfd = sfd;
	fnode->private = private;
	printkdebug(f, "open %s (%p)", fnode->path, ht);

	pthread_rwlock_init(&fnode->lock, NULL);
	return fnode;
}

static int null_close_upcall(struct vuht_entry_t *ht, int sfd, void *private) {
	return 0;
}

/* close a fnode. actually it decrements the usage count and effectively closes
	 the fnode only when the usage count is zero.
	 vu_fnode_close_upcall provides the right function to close each type of
	 file (socket, file, directory etc. */
int vu_fnode_close(struct vu_fnode_t *fnode) {
	int ret_value;
	pthread_rwlock_wrlock(&fnode->lock);
	printkdebug(f, "close %s (%p) count %d", fnode->path, fnode->ht, fnode->count);
	fnode->count -= 1;
	if (fnode->count <= 0) {
		struct vu_fnode_t *oldfnode = fnode;
		if (fnode->vnode)
			vu_vnode_close(fnode->vnode);
		xfree(fnode->path);
		pthread_rwlock_unlock(&fnode->lock);
		/* it should never fail. */
		if (fnode->private == VU_FNODE_CLOSED)
			ret_value = 0;
		else
			ret_value = vu_fnode_close_upcall[S_MODE2TYPE(fnode->mode)](fnode->ht, fnode->sfd, fnode->private);
		pthread_rwlock_destroy(&fnode->lock);
		xfree(oldfnode);
	} else {
		pthread_rwlock_unlock(&fnode->lock);
		ret_value = 0;
	}
	return ret_value;
}

/* increment the usage count of an fnode */
void vu_fnode_dup(struct vu_fnode_t *fnode) {
	if (fnode != NULL) {
		pthread_rwlock_wrlock(&fnode->lock);
		fnode->count++;
		pthread_rwlock_unlock(&fnode->lock);
	}
}

struct vuht_entry_t *vu_fnode_get_ht(struct vu_fnode_t *v) {
	struct vuht_entry_t *ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = v->ht;
	pthread_rwlock_unlock(&v->lock);
	return ret_value;
}

void vu_fnode_get_path(struct vu_fnode_t *v, char *dest,  size_t n) {
	*dest = 0;
	pthread_rwlock_rdlock(&v->lock);
	if (v->path != NULL)
		strncat(dest, v->path, n);
	pthread_rwlock_unlock(&v->lock);
}

char *vu_fnode_get_vpath(struct vu_fnode_t *v) {
	char *ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = vu_vnode_getvpath(v->vnode);
	pthread_rwlock_unlock(&v->lock);
	return ret_value;

}

mode_t vu_fnode_get_mode(struct vu_fnode_t *v) {
	mode_t ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = v->mode;
	pthread_rwlock_unlock(&v->lock);
	return ret_value;
}

int vu_fnode_get_flags(struct vu_fnode_t *v) {
	int ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = v->flags;
	pthread_rwlock_unlock(&v->lock);
	return ret_value;
}

void vu_fnode_set_flags(struct vu_fnode_t *v, int flags) {
	pthread_rwlock_wrlock(&v->lock);
	v->flags = (v->flags & ~UPDATABLE_FLAGS) | (flags & UPDATABLE_FLAGS);
	pthread_rwlock_unlock(&v->lock);
}

int vu_fnode_get_sfd(struct vu_fnode_t *v, void **pprivate) {
	int ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = v->sfd;
	if (pprivate != NULL)
		*pprivate = v->private;
	pthread_rwlock_unlock(&v->lock);
	return ret_value;
}

int vu_fnode_copyinout (struct vu_fnode_t *v, copyfun cp) {
	int ret_value;
	pthread_rwlock_rdlock(&v->lock);
	ret_value = vu_vnode_copyinout(v->vnode, v->path, cp);
	pthread_rwlock_unlock(&v->lock);
	return ret_value;
}

void vu_fnode_get_possize_lock(struct vu_fnode_t *v, off_t *pos, off_t *size) {
	pthread_rwlock_wrlock(&v->lock);
	*pos = v->pos;
	*size = vu_vnode_get_size_lock(v->vnode);
}

void vu_fnode_set_possize_unlock(struct vu_fnode_t *v, off_t pos, off_t size) {
	v->pos = pos;
	vu_vnode_set_size_unlock(v->vnode, size);
	pthread_rwlock_unlock(&v->lock);
}

off_t vu_fnode_getset_size(struct vuht_entry_t *ht, struct vu_stat *stat, off_t size) {
	if (stat == NULL)
		return -1;
	else
		return vu_vnode_getset_size(ht, stat->st_dev, stat->st_ino, size);
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(f, "FILETABLE");
	}

