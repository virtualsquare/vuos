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
#include <limits.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <xcommon.h>
#include <vu_log.h>
#include <vu_inheritance.h>

/* file system entry */
struct vu_fs_t {
	pthread_rwlock_t lock;
	char *cwd;      // current working directory
	char *rootdir;  // current root directory (absolute canonicalized path) */
	mode_t umask;   // current umask
	size_t count;   // number of threads sharing this entry
	int path_rewrite; // true if patnames must be rewritten
};

static __thread struct vu_fs_t *vu_fs = NULL;

static char *vu_fs_set_dir_nolock(char *dir, const char *s)
{
	if (s != NULL) {
		char *newdir = strdup(s);
		if (dir != NULL)
			free(dir);
		return newdir;
	} else
		return dir;
}

void vu_fs_set_cwd(char *wd) {
	pthread_rwlock_wrlock(&vu_fs->lock);
	vu_fs->cwd =
		vu_fs_set_dir_nolock(vu_fs->cwd, wd);
	pthread_rwlock_unlock(&vu_fs->lock);
}

void vu_fs_set_rootdir(char *dir) {
	pthread_rwlock_wrlock(&vu_fs->lock);
	vu_fs->rootdir = vu_fs_set_dir_nolock(vu_fs->rootdir, dir);
	pthread_rwlock_unlock(&vu_fs->lock);
}

mode_t vu_fs_set_umask(mode_t mask) {
	mode_t ret_value;
	pthread_rwlock_wrlock(&vu_fs->lock);
	ret_value = vu_fs->umask;
	vu_fs->umask = mask & 0777;
	pthread_rwlock_unlock(&vu_fs->lock);
	return ret_value;
}

void vu_fs_get_rootdir(char *dest, size_t n) {
	*dest = 0;
	pthread_rwlock_rdlock(&vu_fs->lock);
	strncat(dest, vu_fs->rootdir, n);
	pthread_rwlock_unlock(&vu_fs->lock);
}

int vu_fs_is_chroot(void) {
	char ret_value;
	pthread_rwlock_rdlock(&vu_fs->lock);
	ret_value = (vu_fs->rootdir[1] != '\0');
	pthread_rwlock_unlock(&vu_fs->lock);
	return ret_value;
}

void vu_fs_get_cwd(char *dest, size_t n) {
	*dest = 0;
	pthread_rwlock_rdlock(&vu_fs->lock);
	strncat(dest, vu_fs->cwd, n);
	pthread_rwlock_unlock(&vu_fs->lock);
}

mode_t vu_fs_get_umask(void) {
	mode_t ret_value;
	pthread_rwlock_rdlock(&vu_fs->lock);
	ret_value = vu_fs->umask;
	pthread_rwlock_unlock(&vu_fs->lock);
	return ret_value;
}

static void vu_fs_create(void) {
	struct vu_fs_t *newfs;

	newfs = malloc(sizeof(struct vu_fs_t));
	fatal(newfs);
	newfs->cwd = get_current_dir_name();
	fatal(newfs->cwd);
	newfs->rootdir = strdup("/");
	newfs->umask = umask(0777);
	umask(newfs->umask);
	/* info on root process should never be deallocated */
	newfs->count = 2;
	pthread_rwlock_init(&newfs->lock, NULL);
	vu_fs = newfs;
}

static void *vu_fs_clone(int flags) {
	struct vu_fs_t *newfs;

	if (flags & CLONE_FS) {
		pthread_rwlock_wrlock(&vu_fs->lock);
		newfs = vu_fs;
		newfs->count++;
		pthread_rwlock_unlock(&vu_fs->lock);
		return newfs;
	} else {
		newfs = malloc(sizeof(struct vu_fs_t));
		fatal(newfs);
		pthread_rwlock_rdlock(&vu_fs->lock);
		newfs->cwd = strdup(vu_fs->cwd);
		fatal(newfs->cwd);
		newfs->rootdir = strdup(vu_fs->rootdir);
		fatal(newfs->rootdir);
		newfs->umask = vu_fs->umask;
		pthread_rwlock_unlock(&vu_fs->lock);
		newfs->count = 1;
		pthread_rwlock_init(&newfs->lock, NULL);
	}
	return newfs;
}

static void vu_fs_terminate(void) {
	pthread_rwlock_wrlock(&vu_fs->lock);
	vu_fs->count -= 1;
	if (vu_fs->count == 0) {
		struct vu_fs_t *old_vu_fs = vu_fs;
		xfree(vu_fs->cwd);
		xfree(vu_fs->rootdir);
		vu_fs = NULL;
		pthread_rwlock_unlock(&old_vu_fs->lock);
		pthread_rwlock_destroy(&old_vu_fs->lock);
		xfree(old_vu_fs);
	} else
		pthread_rwlock_unlock(&vu_fs->lock);
}

static void *vu_fs_tracer_upcall(inheritance_state_t state, void *arg) {
	void *ret_value = NULL;
	switch (state) {
		case INH_CLONE:
			ret_value = vu_fs_clone(*(int *)arg);
			break;
		case INH_PTHREAD_CLONE:
			ret_value = vu_fs_clone(CLONE_FS);
			break;
		case INH_START:
		case INH_PTHREAD_START:
			vu_fs = arg;
			break;
		case INH_TERMINATE:
		case INH_PTHREAD_TERMINATE:
			vu_fs_terminate();
			break;
		default:
			break;
	}
	return ret_value;
}

__attribute__((constructor))
	static void init(void) {
		vu_fs_create();
		vu_inheritance_upcall_register(vu_fs_tracer_upcall);
	}
