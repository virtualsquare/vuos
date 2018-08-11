/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
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

#include <vumodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <volatilestream.h>
#include <pthread.h>
#include <strcase.h>
#include <stropt.h>
#include <vustat.h>
#include <vufs.h>

static void create_path(int dirfd, char *path) {
	int pathlen = strlen(path);
	char tpath[pathlen];
	int i;
	for (i = 0; i < pathlen; i++) {
		if (path[i] == '/') {
			tpath[i] = 0;
			mkdirat(dirfd, tpath, 0777);
		}
		tpath[i] = path[i];
	}
}

static void destroy_path(int dirfd, char *path) {
	int pathlen = strlen(path);
  char tpath[pathlen];
	int i;
	strncpy(tpath, path, pathlen);
	for (i = pathlen - 1; i >= 0; i--) {
		if (tpath[i] == '/') {
			tpath[i] = 0;
			if (unlinkat(dirfd, tpath, AT_REMOVEDIR) < 0)
				break;
		}
	}
}

#define CHUNKSIZE 4096
static int copyfile(int srcdirfd, int dstdirfd, char *path, size_t truncate) {
	int fdin = openat(srcdirfd, path, O_RDONLY, 0);
	int fdout = openat(dstdirfd, path, O_WRONLY | O_CREAT | O_TRUNC, 0, 0777);
	if (fdin >= 0 && fdout >= 0) {
		size_t nread, readsize = CHUNKSIZE; 
		char buf[CHUNKSIZE];
		while (1) {
			if (truncate < readsize) readsize = truncate;
			nread = read(fdin, buf, readsize);
			if (nread <= 0)
				break;
			truncate -= nread;
			nread = write(fdout, buf, nread);
			if (nread <= 0)
				break;
		}
		close(fdin);
		close(fdout);
		return nread == 0 ? 0 : -1;
	} else {
		if (fdin >= 0) close(fdin);
		if (fdout >= 0) close(fdout);
		errno = EIO;
		return -1;
	}
}

static int vufs_vdeleted(struct vufs_t *vufs, const char *path) {
	struct vu_stat buf;
	if (vufs->ddirfd >= 0)
		return fstatat(vufs->ddirfd, path, &buf, AT_EMPTY_PATH) == 0 && S_ISREG(buf.st_mode);
	else
		return 0;
}

int vu_vufs_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	int vdeleted;
	pthread_mutex_lock(&(vufs->mutex));
	vdeleted = vufs_vdeleted(vufs, pathname + 1);
  retval = fstatat(vufs->vdirfd, pathname + 1, buf, flags | AT_EMPTY_PATH);
	if (retval < 0  && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = fstatat(vufs->rdirfd, pathname + 1, buf, flags | AT_EMPTY_PATH);
	if (retval == 0)
		 vustat_merge(vufs->ddirfd, pathname + 1, buf);
	pthread_mutex_unlock(&(vufs->mutex));
	printkdebug(V, "LSTAT path:%s retvalue:%d", pathname + 1, retval);
	return retval;
}

int vu_vufs_access(char *path, int mode, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	int vdeleted;
	pthread_mutex_lock(&(vufs->mutex));
	vdeleted = vufs_vdeleted(vufs, path + 1);
	retval = faccessat(vufs->vdirfd, path + 1, mode, flags | AT_EMPTY_PATH);
	if (retval < 0  && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = faccessat(vufs->rdirfd, path + 1, mode, flags | AT_EMPTY_PATH);
	pthread_mutex_unlock(&(vufs->mutex));
	printkdebug(V,"ACCESS path:%s mode:%o retvalue:%d", path, mode, retval);
	return retval;
}

int vu_vufs_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return fchownat(vufs->vdirfd, pathname + 1, owner, group, AT_EMPTY_PATH /* XXX */);
}

int vu_vufs_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return fchmodat(vufs->vdirfd, pathname + 1, mode, AT_EMPTY_PATH /* XXX */);
}

ssize_t vu_vufs_readlink(char *path, char *buf, size_t bufsiz) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	//printk("vu_vufs_readlink %s\n", path);
	return readlinkat(vufs->vdirfd, path + 1, buf, bufsiz);
}

#if 0
int vu_vufs_statfs (const char *pathname, struct statfs *buf, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return -1;
}
#endif

int vu_vufs_unlink (const char *pathname) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return unlinkat(vufs->vdirfd, pathname + 1, AT_EMPTY_PATH);
}

int vu_vufs_mkdir (const char *pathname, mode_t mode) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return mkdirat(vufs->vdirfd, pathname + 1, mode);
}

int vu_vufs_mknod (const char *pathname, mode_t mode, dev_t dev) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return mknodat(vufs->vdirfd, pathname + 1, mode, dev);
}

int vu_vufs_rmdir(const char *pathname) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return unlinkat(vufs->vdirfd, pathname + 1, AT_REMOVEDIR);
}

#if 0
int vu_vufs_truncate(const char *path, off_t length, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return -1;
}
#endif

int vu_vufs_link (const char *target, const char *linkpath) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return linkat(vufs->vdirfd, target + 1, vufs->vdirfd, linkpath + 1, 0 /* XXX */);
}

int vu_vufs_symlink (const char *target, const char *linkpath) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return symlinkat(target,  vufs->vdirfd, linkpath + 1);
}

int vu_vufs_rename (const char *target, const char *linkpath, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return syscall(__NR_renameat2, vufs->vdirfd, target + 1, vufs->vdirfd, linkpath + 1, flags);
}

int vu_vufs_open(const char *pathname, int flags, mode_t mode, void **private) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int vdeleted = 0;
	const char *filepath;
	int retval;
	pathname++;
	filepath = pathname;
	pthread_mutex_lock(&(vufs->mutex));
	/* unfortunately AT_EMPTY_PATH is not supported by openat */
	if (*filepath == 0) 
		filepath = vufs->source;
	else
		vdeleted = vufs_vdeleted(vufs, filepath);
	retval = openat(vufs->vdirfd, filepath, flags, mode);
	if (retval < 0 && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = openat(vufs->rdirfd, pathname, flags, mode);
	if (retval >= 0) {
		int pathlen = strlen(pathname) + 1;
		struct vufs_fdprivate *vufs_fdprivate = 
			malloc(sizeof(struct vufs_fdprivate) + pathlen);
		vufs_fdprivate->getdentsf = NULL;
		strncpy(vufs_fdprivate->path, pathname, pathlen);
		*private = vufs_fdprivate;
	} else
		*private = NULL;
	pthread_mutex_unlock(&(vufs->mutex));
	return retval;
}

int vu_vufs_close(int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	pthread_mutex_lock(&(vufs->mutex));
	retval = close(fd);
	if (retval == 0 && fdprivate != NULL) {
		struct vufs_fdprivate *vufs_fdprivate = fdprivate;
		if (vufs_fdprivate->getdentsf != NULL)
			fclose(vufs_fdprivate->getdentsf);
		free(vufs_fdprivate);
	}
	pthread_mutex_unlock(&(vufs->mutex));
	return retval;
}
