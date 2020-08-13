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
#include <stropt.h>
#include <vufs.h>

/* add an entry to the volatile stream for getdents */
static int vufs_filldir_entry(FILE *f, const char *name, unsigned char type, __ino64_t ino) {
	struct dirent64 entry = {
		.d_ino = ino,
		.d_type = type,
		.d_off = ftello(f),
	};
	static char filler[7];
	unsigned short int namelen = strlen(name) + 1;
	unsigned short int reclen  = offsetof(struct dirent64, d_name) + namelen;
	int ret_value;
	snprintf(entry.d_name, 256, "%s", name);
	/* entries are always 8 bytes aligned */
	entry.d_reclen = (reclen + 7) & (~7);
	ret_value = fwrite(&entry, reclen, 1, f);
	/* add a filler to align the next entry */
	if (entry.d_reclen > reclen)
		ret_value += fwrite(filler, entry.d_reclen - reclen, 1, f);
	return 0;
}

/* check if a name is in the list of already seen names*/
/* the "list" is a concatenation of zero terminated strings.
	 an empty entry is the tag of the end of list */
static int vufs_seen_entry(char *s, char *list) {
	char *scan = list;
	while (*scan) {
		if (strcmp(s, scan) == 0)
			return 1;
		scan += strlen(scan) + 1;
	}
	return 0;
}

static void vufs_filldir(unsigned int fd, struct vufs_t *vufs, struct vufs_fdprivate *vufs_fdprivate) {
	char *seenlist = NULL;
	size_t seenlistlen = 0;
	FILE *seenf = open_memstream(&seenlist, &seenlistlen);
	DIR *dir;
	struct dirent *de;
	int dirfd;
	vufs_fdprivate->getdentsf = volstream_open();
	if (vufs_fdprivate->path[0] == 0)
		dirfd = openat(vufs->vdirfd, vufs->source, O_RDONLY | O_DIRECTORY);
	else
		dirfd = openat(vufs->vdirfd, vufs_fdprivate->path, O_RDONLY | O_DIRECTORY);
	if (dirfd) {
		dir = fdopendir(dirfd);
		if (dir) {
			/* ADD entries in vdirfd (source) */
			while ((de = readdir(dir)) != NULL) {
				if (!(vufs_fdprivate->path[0] == 0 && strcmp(de->d_name, ".-") == 0)) {
					vufs_filldir_entry(vufs_fdprivate->getdentsf, de->d_name, de->d_type, de->d_ino);
					if (vufs->rdirfd >= 0)
						fwrite(de->d_name, strlen(de->d_name) + 1, 1, seenf);
				}
			}
			closedir(dir);
		}
	}
	if (vufs->rdirfd >= 0) {
		/* ADD deleted entries (ddirfd) in seenlist (if merge) */
		if (vufs->ddirfd >= 0) {
			if (vufs_fdprivate->path[0] == 0)
				dirfd = openat(vufs->vdirfd, ".-", O_RDONLY | O_DIRECTORY);
			else
				dirfd = openat(vufs->ddirfd, vufs_fdprivate->path, O_RDONLY | O_DIRECTORY);
			if (dirfd >= 0) {
				dir = fdopendir(dirfd);
				while ((de = readdir(dir)) != NULL) {
					struct vu_stat buf;
					if (fstatat(dirfd, de->d_name, &buf, 0) == 0 && S_ISREG(buf.st_mode))
						fwrite(de->d_name, strlen(de->d_name) + 1, 1, seenf);
				}
				closedir(dir);
			}
		}
		/* write the empty string as the end of the seen list */
		fwrite("", 1, 1, seenf);
		fflush(seenf);
		/* ADD unseen entries in rdirfd (target) (if merge) */
		if (vufs_fdprivate->path[0] == 0)
			dirfd = openat(vufs->rdirfd, vufs->target, O_RDONLY | O_DIRECTORY);
		else
			dirfd = openat(vufs->rdirfd, vufs_fdprivate->path, O_RDONLY | O_DIRECTORY);
		if (dirfd >= 0) {
			dir = fdopendir(dirfd);
			while ((de = readdir(dir)) != NULL) {
				if (! vufs_seen_entry(de->d_name, seenlist))
					vufs_filldir_entry(vufs_fdprivate->getdentsf, de->d_name, de->d_type, de->d_ino);
			}
			closedir(dir);
		}
	}
	fclose(seenf);
	if (seenlist != NULL)
		free(seenlist);
	fseeko(vufs_fdprivate->getdentsf, 0, SEEK_SET);
}

int vu_vufs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int vufs_type = vufs->flags & VUFS_TYPEMASK;
	if (vufs_type == VUFS_MOVE)
		return syscall(__NR_getdents64, fd, dirp, count);
	else if (fdprivate != NULL) {
		int retval;
		pthread_mutex_lock(&(vufs->mutex));
		struct vufs_fdprivate *vufs_fdprivate = fdprivate;
		if (vufs_fdprivate->getdentsf == NULL)
			vufs_filldir(fd, vufs, vufs_fdprivate);
		if (vufs_fdprivate->getdentsf != NULL) {
			retval = fread(dirp, 1, count, vufs_fdprivate->getdentsf);
			if (retval == (int) count) {
				unsigned int bpos = 0;
				struct dirent64 *d;
				char *buf = (char *) dirp;
				while (1) {
					d = (struct dirent64 *) (buf + bpos);
					if (count - bpos < offsetof(struct dirent64, d_name))
						break;
					if (bpos + d->d_reclen > count)
						break;
					bpos += d->d_reclen;
				}
				if (bpos < count) {
					fseeko(vufs_fdprivate->getdentsf, - (int) (count - bpos), SEEK_CUR);
					retval -= count - bpos;
				}
				/* the buffer is so short that it does not fit one
					 entry. Return EINVAL! */
				if (retval == 0) {
					errno = EINVAL;
					retval = -1;
				}
			}
		}
		pthread_mutex_unlock(&(vufs->mutex));
		printkdebug(V, "GETDENTS retvalue:%d", retval);
		return retval;
	} else {
		errno = EBADF;
		return -1;
	}
}

static int skipdir(const char *name, int dotdelete) {
	if (name[0] == 0 || name[0] != '.')
		return 0;
	if (name[1] == 0)
		return 1;
	if (name[1] == '.' && name[2] == 0)
		return 1;
	if (dotdelete && name[1] == '-' && name[2] == 0)
		return 1;
	return 0;
}

static int vufs_enotempty_dir(int fd, int dfd, int dotdelete) {
	DIR *dir;
	struct dirent *de;
	int retval = 0;
	int errno_copy;
	dir = fdopendir(fd);
	while ((de = readdir(dir)) != NULL) {
		if (skipdir(de->d_name, dotdelete) == 0) {
			struct vu_stat buf;
			if (dfd < 0 || fstatat(dfd, de->d_name, &buf, 0) < 0 || !S_ISREG(buf.st_mode)) {
				retval = -1;
				errno = ENOTEMPTY;
				break;
			}
		}
	}
	errno_copy = errno;
	closedir(dir);
	if (dfd >= 0)
		close(dfd);
	errno = errno_copy;
	return retval;
}

int vufs_enotempty_ck(struct vufs_t *vufs, const char *path) {
	int vfd = openat(vufs->vdirfd, *path == 0 ? vufs->source : path, O_RDONLY | O_DIRECTORY);
	int rfd;
	int dfd;
	/* scan virt dir, if there is at least a file, dir is not empty */
	if (vfd >= 0) {
		if (vufs_enotempty_dir(vfd, -1, *path == 0) < 0)
			return -1;
	} else if (errno != ENOENT)
		return -1;
	/* the virt dir either does not exist or it is empty */
	/* try the real directory */
	/* let us first test if the dir has been virtually deleted */
	if (*path == 0)
		dfd = openat(vufs->vdirfd, ".-", O_PATH);
	else
		dfd = openat(vufs->ddirfd, path, O_PATH);
	if (dfd > 0) {
		struct vu_stat buf;
		if (fstatat(dfd, "", &buf, AT_EMPTY_PATH) == 0 && S_ISREG(buf.st_mode)) {
			close(dfd);
			return vfd >= 0 ? 0 : -1;
		}
	}
	/* scan the real dir looking for (undeleted) files */
	rfd = openat(vufs->rdirfd, *path == 0 ? vufs->target : path, O_RDONLY | O_DIRECTORY);
	if (rfd >= 0)
		return vufs_enotempty_dir(rfd, dfd, 0);
	else {
		if (dfd >= 0) close(dfd);
		return vfd >= 0 ? 0 : -1;
	}
}
