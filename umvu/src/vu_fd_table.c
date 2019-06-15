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
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <xcommon.h>
#include <vu_log.h>
#include <vu_inheritance.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <umvu_peekpoke.h>

/* it must be power of two */
#define FD_TABLE_CHUNK 16
#define FDFLAGS_MASK FD_CLOEXEC

struct vu_fd_table_t {
	pthread_rwlock_t lock;
	size_t count;              // number of threads sharing this element

	int table_size;            // size of fnode and flags arrays
	struct vu_fnode_t **fnode; // fd (as seen by the user proc) is the index here
	uint8_t *flags;            // as above. the only flag handled at this level is close_on_exec
};

/* global fd table for nested virtualization */
static struct vu_fd_table_t *vu_n_fd = NULL;

/* thread private fd table
	 (shared by threads created by CLONE_FILES */
static __thread struct vu_fd_table_t *vu_fd = NULL;

#define VU_FD_TABLE(nested) (nested ? vu_n_fd : vu_fd)

static struct vu_fd_table_t *vu_fd_create(void) {
	struct vu_fd_table_t *newfd;

	newfd = malloc(sizeof(struct vu_fd_table_t));
	fatal(newfd);
	newfd->count = 1;
	newfd->table_size = 0;
	newfd->flags = NULL;
	newfd->fnode = NULL;
	pthread_rwlock_init(&newfd->lock, NULL);
	return(newfd);
}

static void *vu_fd_clone(void *arg) {
	int flags = *(int *)arg;
	struct vu_fd_table_t *newfd;

	if (flags & CLONE_FILES) {
		pthread_rwlock_wrlock(&vu_fd->lock);
		newfd = vu_fd;
		newfd->count++;
		pthread_rwlock_unlock(&vu_fd->lock);
		return newfd;
	} else {
		int i;
		newfd = malloc(sizeof(struct vu_fd_table_t));
		fatal(newfd);
		pthread_rwlock_rdlock(&vu_fd->lock);
		newfd->table_size = vu_fd->table_size;
		newfd->fnode = malloc(newfd->table_size * sizeof(newfd->fnode[0]));
		fatal(newfd->fnode);
		newfd->flags = malloc(newfd->table_size * sizeof(newfd->flags[0]));
		fatal(newfd->flags);
		for (i = 0; i < newfd->table_size ; i++) {
			vu_fnode_dup(vu_fd->fnode[i]);
			newfd->fnode[i] = vu_fd->fnode[i];
			newfd->flags[i] = vu_fd->flags[i];
		}
		pthread_rwlock_unlock(&vu_fd->lock);
		pthread_rwlock_init(&newfd->lock, NULL);
		newfd->count=1;
	}
	return newfd;
}

static void vu_fd_terminate(void) {
	pthread_rwlock_wrlock(&vu_fd->lock);
	vu_fd->count -= 1;
	if (vu_fd->count == 0) {
		int i;
		struct vu_fd_table_t *old_vu_fd = vu_fd;
		vu_fd = NULL;
		pthread_rwlock_unlock(&old_vu_fd->lock);
		for (i = 0; i < old_vu_fd->table_size ; i++) {
			if (old_vu_fd->fnode[i] != NULL)
				vu_fnode_close(old_vu_fd->fnode[i]);
		}
		xfree(old_vu_fd->flags);
		xfree(old_vu_fd->fnode);
		pthread_rwlock_destroy(&old_vu_fd->lock);
		xfree(old_vu_fd);
	} else
		pthread_rwlock_unlock(&vu_fd->lock);
}

static void vu_fd_close_on_exec(void) {
	int i;
	pthread_rwlock_wrlock(&vu_fd->lock);
	for (i = 0; i < vu_fd->table_size ; i++) {
		if (vu_fd->fnode[i] != NULL &&
				(vu_fd->flags[i] & FD_CLOEXEC)) {
			vu_fnode_close(vu_fd->fnode[i]);
			vu_fd->fnode[i] = NULL;
			vu_fd->flags[i] = 0;
		}
	}
	pthread_rwlock_unlock(&vu_fd->lock);
}

static void vu_fd_table_resize(struct vu_fd_table_t *fd_table, int fd) {
	if (fd >= fd_table->table_size) {
    int i;
    int new_size = (fd + (FD_TABLE_CHUNK)) & ~(FD_TABLE_CHUNK - 1);
    fd_table->fnode = realloc(fd_table->fnode, new_size * sizeof(fd_table->fnode[0]));
    fatal(fd_table->fnode);
    fd_table->flags = realloc(fd_table->flags, new_size * sizeof(fd_table->flags[0]));
    fatal(fd_table->flags);
    for (i = fd_table->table_size; i < new_size; i++) {
      fd_table->fnode[i] = NULL;
      fd_table->flags[i] = 0;
    }
    fd_table->table_size = new_size;
  }
}

void vu_fd_set_fnode(int fd, int nested, struct vu_fnode_t *fnode, int fdflags) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
  fatal(fd_table);
	pthread_rwlock_wrlock(&fd_table->lock);
	vu_fd_table_resize(fd_table, fd);
	fd_table->fnode[fd] = fnode;
	fd_table->flags[fd] = fdflags & FDFLAGS_MASK;
	pthread_rwlock_unlock(&fd_table->lock);
}

int vu_fd_close(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	int ret_value;
	fatal(fd_table);
	pthread_rwlock_wrlock(&fd_table->lock);
	if (fd >= 0 && fd < fd_table->table_size) {
		struct vu_fnode_t *oldfnode = fd_table->fnode[fd];
		fd_table->fnode[fd] = NULL;
		fd_table->flags[fd] = 0;
		pthread_rwlock_unlock(&fd_table->lock);
		/* fd table must be unlocked for recursion */
		if (oldfnode != NULL)
			ret_value = vu_fnode_close(oldfnode);
		else {
			ret_value = -1;
			errno = EBADF;
		}
	} else {
		ret_value = -1;
		errno = EBADF;
		pthread_rwlock_unlock(&fd_table->lock);
	}
	return ret_value;
}

void vu_fd_dup(int fd, int nested, int oldfd, int fdflags) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
  fatal(fd_table);
  pthread_rwlock_wrlock(&fd_table->lock);
	if (fd >= 0) {
		vu_fd_table_resize(fd_table, fd);
		if (fd_table->fnode[fd] != NULL)
			vu_fnode_close(fd_table->fnode[fd]);
		if (oldfd >= 0 && oldfd < fd_table->table_size) {
			vu_fnode_dup(fd_table->fnode[oldfd]);
			fd_table->fnode[fd] = fd_table->fnode[oldfd];
			fd_table->flags[fd] = fdflags & FDFLAGS_MASK;
		} else {
			fd_table->fnode[fd] = NULL;
			fd_table->flags[fd] = 0;
		}
		pthread_rwlock_unlock(&fd_table->lock);
	}
}

static struct vu_fnode_t *get_fnode_nolock(struct vu_fd_table_t *fd_table, int fd) {
	fatal(fd_table);
	if (fd >= 0 && fd < fd_table->table_size)
		return fd_table->fnode[fd];
	else
		return NULL;
}

static uint8_t *get_flags_addr_nolock(struct vu_fd_table_t *fd_table, int fd) {
	fatal(fd_table);
	if (fd >= 0 && fd < fd_table->table_size)
		return &fd_table->flags[fd];
	else
		return NULL;
}

struct vu_fnode_t *vu_fd_get_fnode(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
  struct vu_fnode_t *fnode;
	pthread_rwlock_rdlock(&fd_table->lock);
  fnode = get_fnode_nolock(fd_table, fd);
  pthread_rwlock_unlock(&fd_table->lock);
  return fnode;
}

struct vuht_entry_t *vu_fd_get_ht(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	struct vu_fnode_t *fnode;
	struct vuht_entry_t *ret_value;
	pthread_rwlock_rdlock(&fd_table->lock);
	fnode = get_fnode_nolock(fd_table, fd);
	ret_value = fnode ?  vu_fnode_get_ht(fnode) : NULL;
	pthread_rwlock_unlock(&fd_table->lock);
	return ret_value;
}

void vu_fd_get_path(int fd, int nested, char *dest,  size_t n) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	if (dest) {
		struct vu_fnode_t *fnode;
		pthread_rwlock_rdlock(&fd_table->lock);
		fnode = get_fnode_nolock(fd_table, fd);
		if (fnode)
			vu_fnode_get_path(fnode, dest, n);
		else
			dest[0] = 0;	
		pthread_rwlock_unlock(&fd_table->lock);
	}
}

mode_t vu_fd_get_mode(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	struct vu_fnode_t *fnode;
	mode_t ret_value;
	pthread_rwlock_rdlock(&fd_table->lock);
	fnode = get_fnode_nolock(fd_table, fd);
	ret_value = fnode ? vu_fnode_get_mode(fnode) : 0;
	pthread_rwlock_unlock(&fd_table->lock);
	return ret_value;
}

int vu_fd_get_fdflags(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	uint8_t *flags_addr;
	int ret_value;
	pthread_rwlock_rdlock(&fd_table->lock);
	flags_addr = get_flags_addr_nolock(fd_table, fd);
	ret_value = flags_addr ? *flags_addr : -1;
	pthread_rwlock_unlock(&fd_table->lock);
	return ret_value;
}

void vu_fd_set_fdflags(int fd, int nested, int flags) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	uint8_t *flags_addr;
	pthread_rwlock_wrlock(&fd_table->lock);
	flags_addr = get_flags_addr_nolock(fd_table, fd);
	if (flags_addr)
		*flags_addr = flags & FDFLAGS_MASK;
	pthread_rwlock_unlock(&fd_table->lock);
}

int vu_fd_get_flflags(int fd, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	struct vu_fnode_t *fnode;
	int ret_value;
	pthread_rwlock_rdlock(&fd_table->lock);
	fnode = get_fnode_nolock(fd_table, fd);
	ret_value = fnode ? vu_fnode_get_flags(fnode) : -1;
	pthread_rwlock_unlock(&fd_table->lock);
	return ret_value;
}

void vu_fd_set_flflags(int fd, int nested, int flags) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	struct vu_fnode_t *fnode;
	pthread_rwlock_rdlock(&fd_table->lock);
	fnode = get_fnode_nolock(fd_table, fd);
	if (fnode)
		vu_fnode_set_flags(fnode, flags);
	pthread_rwlock_unlock(&fd_table->lock);
}

int vu_fd_get_sfd(int fd, void **pprivate, int nested) {
	struct vu_fd_table_t *fd_table = VU_FD_TABLE(nested);
	struct vu_fnode_t *fnode;
	int ret_value;
	pthread_rwlock_rdlock(&fd_table->lock);
	fnode = get_fnode_nolock(fd_table, fd);
	ret_value = fnode ? vu_fnode_get_sfd(fnode, pprivate) : -1;
	pthread_rwlock_unlock(&fd_table->lock);
	return ret_value;
}

static void *vu_fd_tracer_upcall(inheritance_state_t state, void *arg) {
	void *ret_value = NULL;
	switch (state) {
		case INH_CLONE:
			ret_value = vu_fd_clone(arg);
			break;
		case INH_START:
			vu_fd = arg;
			break;
		case INH_EXEC:
			vu_fd_close_on_exec();
			break;
		case INH_TERMINATE:
			vu_fd_terminate();
			break;
		default:
			break;
	}
	return ret_value;
}

__attribute__((constructor))
	static void init(void) {
		vu_n_fd = vu_fd_create();
		vu_fd = vu_fd_create();
		vu_inheritance_upcall_register(vu_fd_tracer_upcall);
	}


