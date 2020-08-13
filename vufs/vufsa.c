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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vufs.h>
#include <vufsa.h>

static inline void vufs_lock(struct vufs_t *vufs) {
	pthread_mutex_lock(&(vufs->mutex));
}

static inline void vufs_unlock(struct vufs_t *vufs) {
	pthread_mutex_unlock(&(vufs->mutex));
}

static inline int o_is_creat_excl(int flags) {
	return (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
}

static inline int o_is_unlink(int flags) {
	return flags == O_UNLINK;
}

static int vufs_vdeleted(struct vufs_t *vufs, const char *path) {
	struct vu_stat buf;
	if (vufs->ddirfd >= 0) {
		if (fstatat(vufs->ddirfd, path, &buf, AT_EMPTY_PATH) == 0)
			return S_ISREG(buf.st_mode);
		else
			return errno == ENOTDIR; // a component in the path has been deleted
	} else
		return 0;
}

static inline int vufs_vexist (struct vufs_t *vufs, const char *path, int flags) {
	struct vu_stat buf;
	if (fstatat(vufs->vdirfd, path, &buf, flags | AT_EMPTY_PATH) == 0)
		return 1;
	else if (errno == ENOENT)
		return 0;
	else
		return 1;
}

static inline int vufs_rexist (struct vufs_t *vufs, const char *path, int flags) {
	struct vu_stat buf;
	if (fstatat(vufs->rdirfd, path, &buf, flags | AT_EMPTY_PATH) == 0)
		return 1;
	else if (errno == ENOENT)
		return 0;
	else
		return 1;
}

static vufsa_status vufsa_rdonly(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			return VUFSA_DOVIRT;
		case VUFSA_DOVIRT:
			if (rv < 0 && errno == ENOENT) {
				if (vufs_vdeleted(vufs, path)) {
					errno = ENOENT;
					return VUFSA_FINAL;
				} else
					return VUFSA_DOREAL;
			} else
				return VUFSA_FINAL;
		case VUFSA_DOREAL:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_move(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			return VUFSA_DOVIRT;
		case VUFSA_DOVIRT:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	return VUFSA_EXIT;
}

static vufsa_status vufsa_merge(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, 0) || vufs_vdeleted(vufs, path)) {
				errno = EROFS;
				return VUFSA_ERR;
			} else
				return VUFSA_DOREAL;
		case VUFSA_DOREAL:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_merge_unlink(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, AT_SYMLINK_NOFOLLOW)) {
				errno = EROFS;
				return VUFSA_ERR;
			} else if (vufs_vdeleted(vufs, path)) {
				errno = ENOENT;
				return VUFSA_ERR;
			} else
				return VUFSA_DOREAL;
		case VUFSA_DOREAL:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_cow(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, 0) || vufs_vdeleted(vufs, path))
				return VUFSA_DOVIRT;
			else
				return VUFSA_DOCOPY;
		case VUFSA_DOCOPY:
			return VUFSA_DOVIRT;
		case VUFSA_DOVIRT:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_cow_creat(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_rexist(vufs, path, 0) && !vufs_vdeleted(vufs, path)) {
				errno = EEXIST;
				return VUFSA_ERR;
			} else
				return VUFSA_DOVIRT;
		case VUFSA_DOVIRT:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_cow_unlink(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, AT_SYMLINK_NOFOLLOW))
				return VUFSA_DOVIRT;
			else if (vufs_vdeleted(vufs, path)) {
				errno = ENOENT;
				return VUFSA_ERR;
			} else if (vufs_rexist(vufs, path, AT_SYMLINK_NOFOLLOW))
				return VUFSA_VUNLINK;
			else {
				errno = ENOENT;
				return VUFSA_ERR;
			}
		case VUFSA_DOVIRT:
			if (rv == 0 && vufs_rexist(vufs, path, 0) && !vufs_vdeleted(vufs, path))
				return VUFSA_VUNLINK;
			else
				return VUFSA_FINAL;
		case VUFSA_VUNLINK:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_mincow(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, 0) || vufs_vdeleted(vufs, path))
				return VUFSA_DOVIRT;
			else
				return VUFSA_DOREAL;
		case VUFSA_DOREAL:
			if (rv < 0 && (errno == EACCES || errno == EPERM))
				return VUFSA_DOCOPY;
			else
				return VUFSA_FINAL;
		case VUFSA_DOCOPY:
			return VUFSA_DOVIRT;
		case VUFSA_DOVIRT:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_mincow_creat(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_rexist(vufs, path, 0)) {
				if (vufs_vdeleted(vufs, path))
					return VUFSA_DOVIRT;
				else {
					errno = EEXIST;
					return VUFSA_ERR;
				}
			} else
				return VUFSA_DOREAL;
		case VUFSA_DOREAL:
			if (rv < 0 && (errno == EACCES || errno == ENOENT || errno == EPERM))
				return VUFSA_DOVIRT;
			else
				return VUFSA_FINAL;
		case VUFSA_DOVIRT:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_mincow_unlink(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_START:
			vufs_lock(vufs);
			if (vufs_vexist(vufs, path, AT_SYMLINK_NOFOLLOW))
				return VUFSA_DOVIRT;
			else if (vufs_vdeleted(vufs, path)) {
				errno = ENOENT;
				return VUFSA_ERR;
			} else if (vufs_rexist(vufs, path, AT_SYMLINK_NOFOLLOW))
				return VUFSA_DOREAL;
			else {
				errno = ENOENT;
				return VUFSA_ERR;
			}
		case VUFSA_DOREAL:
			if (rv < 0 && (errno == EACCES || errno == EPERM))
				return VUFSA_VUNLINK;
			else
				return VUFSA_FINAL;
		case VUFSA_DOVIRT:
			if (rv == 0 && vufs_rexist(vufs, path, AT_SYMLINK_NOFOLLOW) && !vufs_vdeleted(vufs, path))
				return VUFSA_VUNLINK;
			else
				return VUFSA_FINAL;
		case VUFSA_VUNLINK:
			return VUFSA_FINAL;
		case VUFSA_FINAL:
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	}
	vufs_unlock(vufs);
	return VUFSA_EXIT;
}

static vufsa_status vufsa_err(vufsa_status status,
		struct vufs_t *vufs, const char *path, int rv) {
	switch (status) {
		case VUFSA_ERR:
			break;
		default:
			return VUFSA_ERR;
	};
	return VUFSA_EXIT;
}

vufsa_next vufsa_select(struct vufs_t *vufs, int open_flags) {
	int vufs_type = vufs->flags & VUFS_TYPEMASK;
	if (vufs_type == VUFS_MOVE)
		return vufsa_move;
	if (vufs_type == VUFS_MERGE) {
		if (o_is_creat_excl(open_flags))
			return vufsa_merge;
		else if (o_is_unlink(open_flags))
			return vufsa_merge_unlink;
		else if ((open_flags & O_ACCMODE) == O_RDONLY)
			return vufsa_rdonly;
		else
			return vufsa_merge;
	} else if (vufs_type == VUFS_COW) {
		if (o_is_creat_excl(open_flags))
			return vufsa_cow_creat;
		else if (o_is_unlink(open_flags))
			return vufsa_cow_unlink;
		else if ((open_flags & O_ACCMODE) == O_RDONLY)
			return vufsa_rdonly;
		else
			return vufsa_cow;
	} else if (vufs_type == VUFS_MINCOW) {
		if (o_is_creat_excl(open_flags))
			return vufsa_mincow_creat;
		else if (o_is_unlink(open_flags))
			return vufsa_mincow_unlink;
		else if ((open_flags & O_ACCMODE) == O_RDONLY)
			return vufsa_rdonly;
		else
			return vufsa_mincow;
	}
	return vufsa_err;
}
