/*
 * vudevfuse: /dev/fuse - virtual fuse kernel support
 * Copyright 2022 Renzo Davoli
 *     Virtualsquare & University of Bologna
 *
 * vudevfuse_ops.c: manage calls from user processes
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
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <linux/fuse.h>

#include <volatilestream.h>
#include <vumodule.h>

#include <vudevfuse.h>
#include <devfuse.h>
#include <fusenode.h>

VU_PROTOTYPES(fuse)

	struct fusefile_t {
		pthread_mutex_t mutex;
		uint64_t nodeid;
		mode_t filemode;
		uint64_t fh;
		int flags;
		uint32_t open_flags;
#if !(VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
		off_t pos;
		off_t size;
#endif
		FILE *dir;
	};

// for lstat parent arg:
#define LSTAT_THIS 0
#define LSTAT_PARENT 1

static void fuse2stat(struct vu_stat *buf, struct fuse_attr *fa) {
	memset(buf, 0, sizeof(*buf));
	buf->st_ino = fa->ino;
	buf->st_size = fa->size;
	buf->st_blocks = fa->blocks;
	buf->st_atime = fa->atime;
	buf->st_mtime = fa->mtime;
	buf->st_ctime = fa->ctime;
	buf->st_atim.tv_nsec = fa->atimensec;
	buf->st_mtim.tv_nsec = fa->mtimensec;
	buf->st_ctim.tv_nsec = fa->ctimensec;
	buf->st_mode = fa->mode;
	buf->st_nlink = fa->nlink;
	buf->st_uid = fa->uid;
	buf->st_gid = fa->gid;
	buf->st_rdev = fa->rdev;
	buf->st_blksize = fa->blksize;
}

static void fuse2statfs(struct statfs *buf, struct fuse_kstatfs *fs) {
	buf->f_type = FUSE_SUPER_MAGIC;
	buf->f_blocks = fs->blocks;
	buf->f_bfree = fs->bfree;
	buf->f_bavail = fs->bavail;
	buf->f_files = fs->files;
	buf->f_ffree = fs->ffree;
	buf->f_bsize = fs->bsize;
	buf->f_namelen = fs->namelen;
	buf->f_frsize = fs->frsize;
}

#define err_return_unlock(MUTEX, ERRNO) \
	do { \
		pthread_mutex_unlock(MUTEX); \
		errno = (ERRNO); \
		return -1; \
	} while (0);

static const char *fuse_basename(const char *path) {
	const char *basename = strrchr(path, '/');
	if (basename == NULL || basename[1] == 0)
		return NULL;
	return basename + 1;
}

static int fuse_getstat(struct fusemount_t *fusemount,  char *path,
		int dirlen, struct fuse_attr *attr, uint64_t dirid, uint64_t *nodeid) {
	char *name = path + dirlen + 1;
	//printf("path |%s| dir |%.*s| name |%s| %p\n", path, dirlen, path, name, nodeid);
	*nodeid = fn_get(fusemount->fnbuf, path, attr);
	if (*nodeid == 0) {
		struct fuse_entry_out entryout;
		int err = vu_devfuse_conversation(fusemount, FUSE_LOOKUP, dirid,
				IOV1(name, strlen(name) + 1),
				IOV1(&entryout, sizeof(entryout)), NULL);
		if (err < 0)
			return errno = -err, -1;
		*nodeid = entryout.nodeid;
		fn_add(fusemount->fnbuf, path, &entryout);
		if (attr)
			*attr = entryout.attr;
	} else if (attr != NULL && attr->mode == 0) {
		struct fuse_getattr_in attrin = { 0 };
		struct fuse_attr_out attrout;
		int err = vu_devfuse_conversation(fusemount, FUSE_GETATTR, *nodeid,
				IOV1(&attrin, sizeof(attrin)),
				IOV1(&attrout, sizeof(attrout)), NULL);
		if (err < 0)
			return errno = -err, -1;
		fn_updatenode(fusemount->fnbuf, *nodeid, &attrout);
		*attr = attrout.attr;
	}
	return 0;
}

static int fuse_recstat(struct fusemount_t *fusemount, char *path,
		struct fuse_attr *attr, uint64_t *nodeid) {
	char *slash = strrchr(path, '/');
	// printf("rec %s\n", path);
	if (slash) {
		uint64_t dirid;
		*slash = 0;
		if (fuse_recstat(fusemount, path, NULL, &dirid) < 0)
			return -1;
		*slash = '/';
		return fuse_getstat(fusemount, path, slash - path, attr, dirid, nodeid);
	} else
		return fuse_getstat(fusemount, path, 0, attr, FUSE_ROOT_ID, nodeid);
}

static int path_len(const char *path, int parent) {
	if (parent) {
		char *slash = strrchr(path, '/');
		if (slash)
			return slash - path;
		else
			return 0;
	} else
		return strlen(path);
}

static int fuse_lstat(struct fusemount_t *fusemount, const char *path,
		struct vu_stat *buf, uint64_t *nodeid, int parent) {
	int pathlen = path_len(path, parent);
	char pathbuf[pathlen + 1];
	sprintf(pathbuf, "%.*s", pathlen, path);
	if (pathbuf[1] == 0) pathbuf[0] = 0; // '/' exception
	uint64_t rnodeid;
	struct fuse_attr attr;
	int staterr = fuse_recstat(fusemount, pathbuf, &attr, &rnodeid);
	if (staterr < 0)
		return staterr;
	if (nodeid)
		*nodeid = rnodeid;
	if (buf)
		fuse2stat(buf, &attr);
	return 0;
}

static void fuse_invalidate_attr(struct fusemount_t *fusemount, uint64_t nodeid)  {
	struct fuse_attr_out attrout = {
		.attr_valid = -1
	};
	fn_updatenode(fusemount->fnbuf, nodeid, &attrout);
}

int vu_fuse_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_lstat(pathname, buf, flags, sfd, fdprivate);

	printkdebug(U,"LSTAT %s", pathname);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	int retval = fuse_lstat(fusemount, pathname, buf, NULL, LSTAT_THIS);

	/* LRU cleaning of fnbuf */
	uint64_t nodeid, nlookup;
	while ((nodeid = fn_forgetlru(fusemount->fnbuf, &nlookup)) > 0) {
		struct fuse_forget_in forgetin = {
			.nlookup = nlookup
		};

		vu_devfuse_conversation(fusemount, FUSE_FORGET, nodeid,
				IOV1(&forgetin, sizeof(forgetin)),
				IOV_NOREPLY, NULL);
	}

	return retval;
}

int vu_fuse_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_open(pathname, flags, mode, fdprivate);
	printkdebug(U,"OPEN path:%s flags:0x%x", pathname, flags);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);

	if (((flags & O_ACCMODE) != O_RDONLY) && (fusemount->mountflags & MS_RDONLY))
		return errno = EROFS, -1;

	struct vu_stat statbuf;
	uint64_t nodeid;
	mode_t filemode = 0;
	struct fusefile_t *fusefile = malloc(sizeof(*fusefile));

	if (fusefile == NULL)
		return errno = ENOMEM, -1;

	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	struct fuse_open_out openout;

	if (staterr < 0 && errno == ENOENT && (flags & O_CREAT)) {
		uint64_t dirid;
		staterr = fuse_lstat(fusemount, pathname, &statbuf, &dirid, LSTAT_PARENT);
		if (staterr < 0)
			return free(fusefile), -1;

		const char *basename = fuse_basename(pathname);
		if (basename == NULL)
			return free(fusefile), errno = EINVAL, -1;

		struct fuse_create_in createin = {
			.flags = flags,
			.mode = S_IFREG | mode,
			.umask = vu_mod_getumask()
		};
		struct fuse_entry_out entryout;

		int err = vu_devfuse_conversation(fusemount, FUSE_CREATE, dirid,
				IOV2(&createin, sizeof(createin), basename, strlen(basename) + 1),
				IOV2(&entryout, sizeof(entryout), &openout, sizeof(openout)), NULL);

		if (err < 0)
			return free(fusefile), errno = -err, -1;

		nodeid = entryout.nodeid;
		filemode = entryout.attr.mode;
		fn_add(fusemount->fnbuf, pathname, &entryout);
	} else {
		if (staterr < 0)
			return free(fusefile), -1;

		filemode = statbuf.st_mode;
		int fuse_open_opendir =
			(S_ISDIR(filemode)) ? FUSE_OPENDIR : FUSE_OPEN;

		struct fuse_open_in openin = {
			.flags = flags
		};
		int err = vu_devfuse_conversation(fusemount, fuse_open_opendir, nodeid,
				IOV1(&openin, sizeof(openin)),
				IOV1(&openout, sizeof(openout)), NULL);

		if (err < 0)
			return free(fusefile), errno = -err, -1;
	}

	pthread_mutex_init(&(fusefile->mutex), NULL);
	fusefile->nodeid = nodeid;
	fusefile->filemode = filemode;
	fusefile->fh = openout.fh;
	fusefile->flags = flags;
	fusefile->open_flags = openout.open_flags;
#if !(VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
	fusefile->size = statbuf.st_size;
	fusefile->pos = 0;
#endif
	fusefile->dir = NULL;

	*fdprivate = fusefile;
	return 0;
}

int vu_fuse_close(int fd, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_close(fd, fdprivate);
	printkdebug(U,"CLOSE %d", fd);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;
	/* XXX */
	if (fusefile == NULL) {
		printk("ERR vu_fuse_close\n");
		return errno = EIO, -1;
	}

	pthread_mutex_lock(&(fusefile->mutex));
	int fuse_rel_reldir =
		(S_ISDIR(fusefile->filemode)) ? FUSE_RELEASEDIR : FUSE_RELEASE;

	struct fuse_release_in releasein = {
		.fh = fusefile->fh
	};

	int err = vu_devfuse_conversation(fusemount, fuse_rel_reldir, fusefile->nodeid,
			IOV1(&releasein, sizeof(releasein)),
			IOV0, NULL);

	if (err < 0)
		err_return_unlock(&(fusefile->mutex), -err);

	if (fusefile->dir != NULL)
		fclose(fusefile->dir);

	fuse_invalidate_attr(fusemount, fusefile->nodeid);
	pthread_mutex_unlock(&(fusefile->mutex));
	pthread_mutex_destroy(&(fusefile->mutex));
	free(fusefile);

	return 0;
}

int vu_fuse_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_epoll_ctl(epfd, op, fd, event,fdprivate);
	return errno = ENOSYS, -1;
}

ssize_t vu_fuse_read(int fd, void *buf, size_t count, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_read(fd, buf, count, fdprivate);
#if (VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
	return vu_devfuse_nosys();
#else
	printkdebug(U,"READ %d count=%zd", fd, count);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;
	pthread_mutex_lock(&(fusefile->mutex));

	struct fuse_read_in readin = {
		.fh = fusefile->fh,
		.offset = fusefile->pos,
		.size = count,
		.flags = fusefile->flags
	};

	int err = vu_devfuse_conversation(fusemount, FUSE_READ, fusefile->nodeid,
			IOV1(&readin, sizeof(readin)),
			IOV1(buf, count), &count);

	if (err < 0)
		err_return_unlock(&(fusefile->mutex), -err);

	fusefile->pos += count;

	pthread_mutex_unlock(&(fusefile->mutex));
	return count;
#endif
}

ssize_t vu_fuse_write(int fd, const void *buf, size_t count, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_write(fd, buf, count, fdprivate);
#if (VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
	return vu_devfuse_nosys();
#else
	printkdebug(U,"WRITE %d count=%zd", fd, count);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;
	pthread_mutex_lock(&(fusefile->mutex));

	if ((fusefile->flags & O_ACCMODE) == O_RDONLY)
		err_return_unlock(&(fusefile->mutex), EBADF);

	/* incomplete emulation of O_APPEND */
	if (fusefile->flags & O_APPEND)
		fusefile->pos = fusefile->size;

	struct fuse_write_in writein = {
		.fh = fusefile->fh,
		.offset = fusefile->pos,
		.size = count,
		.flags = fusefile->flags
	};
	struct fuse_write_out writeout;

	int err = vu_devfuse_conversation(fusemount, FUSE_WRITE, fusefile->nodeid,
			IOV2(&writein, sizeof(writein), buf, count),
			IOV1(&writeout, sizeof(writeout)), NULL);

	if (err < 0)
		err_return_unlock(&(fusefile->mutex), -err);

	count = writeout.size;
	fusefile->pos += count;
	if (fusefile->pos > fusefile->size)
		fusefile->size = fusefile->pos;

	pthread_mutex_unlock(&(fusefile->mutex));
	return count;
#endif
}

static void fuse_filldir(FILE *f, const char *name, unsigned short int namelen,
		unsigned char type, __ino64_t ino) {
	/* glibc hides enries having d_ino == 0 */
	struct dirent64 entry = {
		.d_ino = ino == 0 ? (ino_t) -1 : ino,
		.d_type = type,
		.d_off = ftello(f),
	};
	static char filler[7];
	unsigned short int reclen  = offsetof(struct dirent64, d_name) + namelen + 1;
	int ret_value;
	snprintf(entry.d_name, 256, "%.*s", namelen, name);
	/* entries are always 8 bytes aligned */
	entry.d_reclen = (reclen + 7) & (~7);
	ret_value = fwrite(&entry, reclen, 1, f);
	/* add a filler to align the next entry */
	if (entry.d_reclen > reclen)
		ret_value += fwrite(filler, entry.d_reclen - reclen, 1, f);
}

#define FUSE_INBUF_LEN 4080
static void populate_dir(struct fusemount_t *fusemount, struct fusefile_t *fusefile) {
	if ((fusefile->dir = volstream_open()) == NULL)
		return;

	struct fuse_read_in readin = {
		.fh = fusefile->fh,
		.size = FUSE_INBUF_LEN,
		.offset = 0
	};

	for (;;) {
		char inbuf[FUSE_INBUF_LEN];
		size_t retcount;
		int err = vu_devfuse_conversation(fusemount, FUSE_READDIR, fusefile->nodeid,
				IOV1(&readin, sizeof(readin)),
				IOV1(inbuf, FUSE_INBUF_LEN), &retcount);
		if (retcount <= 0 || err < 0)
			break;

		for (struct fuse_dirent *fde = (void *) inbuf;
				(char *) fde < (inbuf + retcount);
				fde = (void *)(((char *)(fde + 1)) + ((fde->namelen + 7) & (~7))) )  {
			fuse_filldir(fusefile->dir, fde->name, fde->namelen, fde->type, fde->ino);
			readin.offset = fde->off;
		}
	}
}

int vu_fuse_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate) {
	printkdebug(U,"GETDENTS %d", fd);
	struct vuht_entry_t *ht = vu_mod_getht();
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;
	size_t freadout;

	pthread_mutex_lock(&(fusefile->mutex));
	if (fusefile->dir == NULL) {
		populate_dir(fusemount, fusefile);
		fseek(fusefile->dir, 0, SEEK_SET);
	}
	pthread_mutex_unlock(&(fusefile->mutex));

	freadout = fread(dirp, 1, count, fusefile->dir);
	/* if the buffer is full the last entry might be incomplete.
		 update freadout to drop the last incomplete entry,
		 and seek back the position in the file to reread it
		 from its beginning at the next getdents64 */
	if (freadout == count) {
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
			fseeko(fusefile->dir, - (int) (count - bpos), SEEK_CUR);
			freadout -= count - bpos;
		}
		/* the buffer is so short that it does not fit one
			 entry. Return EINVAL! */
		if (freadout == 0) {
			errno = EINVAL;
			return -1;
		}
	}
	return freadout;
}

ssize_t vu_fuse_readlink(char *path, char *buf, size_t bufsiz) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"READLINK path:%s", path);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);

	struct vu_stat statbuf;
	uint64_t nodeid;

	int staterr = fuse_lstat(fusemount, path, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;
	// check if symlink

	size_t retsize;
	int err = vu_devfuse_conversation(fusemount, FUSE_READLINK, nodeid,
			IOV0,
			IOV1(buf, bufsiz), &retsize);

	if (err < 0)
		return errno = -err, -1;

	if (retsize < bufsiz) buf[retsize] = 0;

	return retsize;
}

int vu_fuse_statfs (const char *pathname, struct statfs *buf, int fd, void *fdprivate) {
	(void) pathname;
	(void) fd;
	(void) fdprivate;
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"STATFS");
	struct fusemount_t *fusemount = vuht_get_private_data(ht);

	struct fuse_kstatfs fusebuf;
	int err = vu_devfuse_conversation(fusemount, FUSE_STATFS, FUSE_ROOT_ID,
			IOV0,
			IOV1(&fusebuf, sizeof(fusebuf)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fuse2statfs(buf, &fusebuf);
	return 0;
}

#if !(VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
off_t vu_fuse_lseek(int fd, off_t offset, int whence, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	(void) fd;
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
/* XXX fix: concurrent access */
	printkdebug(U,"LSEEK %d offset=%zd whence=%d", offset, whence);
	struct fusefile_t *fusefile = fdprivate;
	pthread_mutex_lock(&(fusefile->mutex));

	switch (whence) {
		case SEEK_SET: fusefile->pos = offset; break;
		case SEEK_CUR: fusefile->pos += offset; break;
		case SEEK_END: fusefile->pos = fusefile->size + offset; break;
		default: return errno = EINVAL, -1;
	}

	if (fusefile->pos < 0) fusefile->pos = 0;

	pthread_mutex_unlock(&(fusefile->mutex));
	return fusefile->pos;
}
#endif

/* access could be emulated using stat but local uid/gid may not be
	 consistent with Fuse filesytem's uid/gid */

int vu_fuse_access(char *path, int mode, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"ACCESS %s mode=%zd flags=%d", path, mode, flags);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct vu_stat statbuf;
	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, path, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	struct fuse_access_in accessin = {
		.mask = mode
	};
	int err = vu_devfuse_conversation(fusemount, FUSE_ACCESS, nodeid,
			IOV1(&accessin, sizeof(accessin)),
			IOV0, NULL);
	if (err < 0)
		return errno = -err, -1;
	return 0;
}

ssize_t vu_fuse_pread64(int fd, void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"PREAD %d count=%zd offset=%zd", fd, count, offset);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;

	struct fuse_read_in readin = {
		.fh = fusefile->fh,
		.offset = offset,
		.size = count,
		.flags = flags
	};

	int err = vu_devfuse_conversation(fusemount, FUSE_READ, fusefile->nodeid,
			IOV1(&readin, sizeof(readin)),
			IOV1(buf, count), &count);

	if (err < 0)
		return errno = -err, -1;

	return count;
}

ssize_t vu_fuse_pwrite64(int fd, const void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"PWRITE %d count=%zd offset=%zd", fd, count, offset);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	struct fusefile_t *fusefile = fdprivate;

	if ((fusefile->flags & O_ACCMODE) == O_RDONLY)
		return errno = EBADF, -1;

	struct fuse_write_in writein = {
		.fh = fusefile->fh,
		.offset = offset,
		.size = count,
		.flags = fusefile->flags
	};
	struct fuse_write_out writeout;

	int err = vu_devfuse_conversation(fusemount, FUSE_WRITE, fusefile->nodeid,
			IOV2(&writein, sizeof(writein), buf, count),
			IOV1(&writeout, sizeof(writeout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	count = writeout.size;

#if !(VUDEVFUSE_MODULE_FLAGS & VU_USE_PRW)
	off_t cksize = offset + count;
	if (cksize > fusefile->size)
		fusefile->size = cksize;
#endif

	return count;
}

int vu_fuse_mkdir(const char *pathname, mode_t mode) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"MKDIR path:%s mode:%x", pathname, mode);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;

	struct vu_stat statbuf;

	uint64_t dirid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(pathname);
	if (basename == NULL)
		return errno = EINVAL, -1;

	struct fuse_mkdir_in mkdirin = {
		.mode = mode,
		.umask = vu_mod_getumask()
	};
	struct fuse_entry_out entryout;

	int err = vu_devfuse_conversation(fusemount, FUSE_MKDIR, dirid,
			IOV2(&mkdirin, sizeof(mkdirin), basename, strlen(basename) + 1),
			IOV1(&entryout, sizeof(entryout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_add(fusemount->fnbuf, pathname, &entryout);
	return 0;
}

int vu_fuse_mknod(const char *pathname, mode_t mode, dev_t dev) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"MKNOD path:%s mode:%x dev=%x", pathname, mode, dev);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t dirid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(pathname);
	if (basename == NULL)
		return errno = EINVAL, -1;

	struct fuse_mknod_in mknodin = {
		.mode = mode,
		.rdev = dev,
		.umask = vu_mod_getumask()
	};
	struct fuse_entry_out entryout;

	int err = vu_devfuse_conversation(fusemount, FUSE_MKNOD, dirid,
			IOV2(&mknodin, sizeof(mknodin), basename, strlen(basename) + 1),
			IOV1(&entryout, sizeof(entryout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_add(fusemount->fnbuf, pathname, &entryout);
	return 0;
}

int vu_fuse_unlink(const char *pathname) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"UNLINK path:%s", pathname);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	uint64_t dirid;
	staterr = fuse_lstat(fusemount, pathname, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(pathname);
	if (basename == NULL)
		return errno = EINVAL, -1;

	int err = vu_devfuse_conversation(fusemount, FUSE_UNLINK, dirid,
			IOV1(basename, strlen(basename) + 1),
			IOV0, NULL);

	if (err < 0)
		return errno = -err, -1;

	uint64_t nlookup;
	if (fn_delnode(fusemount->fnbuf, nodeid, &nlookup) > 0) {
		struct fuse_forget_in forgetin = {
			.nlookup = nlookup
		};

		vu_devfuse_conversation(fusemount, FUSE_FORGET, nodeid,
				IOV1(&forgetin, sizeof(forgetin)),
				IOV_NOREPLY, NULL);
	}
	return 0;
}

int vu_fuse_rmdir(const char *pathname) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"RMDIR path:%s", pathname);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	uint64_t dirid;
	staterr = fuse_lstat(fusemount, pathname, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(pathname);
	if (basename == NULL)
		return errno = EINVAL, -1;

	int err = vu_devfuse_conversation(fusemount, FUSE_RMDIR, dirid,
			IOV1(basename, strlen(basename) + 1),
			IOV0, NULL);

	if (err < 0)
		return errno = -err, -1;

	uint64_t nlookup;
	if (fn_delnode(fusemount->fnbuf, nodeid, &nlookup) > 0) {
		struct fuse_forget_in forgetin = {
			.nlookup = nlookup
		};

		vu_devfuse_conversation(fusemount, FUSE_FORGET, nodeid,
				IOV1(&forgetin, sizeof(forgetin)),
				IOV_NOREPLY, NULL);
	}
	return 0;
}

int vu_fuse_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	(void) fd;
	(void) fdprivate;
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"CHMOD path:%s mode:%d", pathname, mode);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	struct fuse_setattr_in setattrin = {
		.valid = FATTR_MODE,
		.mode = (statbuf.st_mode & ~ALLPERMS) | (mode & ALLPERMS)
	};
	struct fuse_attr_out attrout;

	int err = vu_devfuse_conversation(fusemount, FUSE_SETATTR, nodeid,
			IOV1(&setattrin, sizeof(setattrin)),
			IOV1(&attrout, sizeof(attrout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_updatenode(fusemount->fnbuf, nodeid, &attrout);
	return 0;
}

int vu_fuse_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	(void) fd;
	(void) fdprivate;
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"CHOWN path:%s uid:%d gid=%d", pathname, owner, group);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	struct fuse_setattr_in setattrin = {
		.valid = ((owner == ((uid_t) -1)) ? 0 : FATTR_UID) |
			((group == ((uid_t) -1)) ? 0 : FATTR_GID),
		.uid = (owner == ((uid_t) -1)) ? 0 : owner,
		.gid = (group == ((gid_t) -1)) ? 0 : group
	};

	struct fuse_attr_out attrout;

	int err = vu_devfuse_conversation(fusemount, FUSE_SETATTR, nodeid,
			IOV1(&setattrin, sizeof(setattrin)),
			IOV1(&attrout, sizeof(attrout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_updatenode(fusemount->fnbuf, nodeid, &attrout);
	return 0;
}

int vu_fuse_utimensat(int dirfd, const char *pathname, \
		const struct timespec times[2], int flags, int fd, void *fdprivate) {
	(void) dirfd;
	(void) flags;
	(void) fd;
	(void) fdprivate;
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"UTIMENSAT path:%s", pathname);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	struct fuse_setattr_in setattrin = {
		.valid = FATTR_ATIME | FATTR_MTIME,
		.atime = times[0].tv_sec,
		.atimensec = times[0].tv_nsec,
		.mtime = times[1].tv_sec,
		.mtimensec = times[1].tv_nsec
	};

	struct fuse_attr_out attrout;

	int err = vu_devfuse_conversation(fusemount, FUSE_SETATTR, nodeid,
			IOV1(&setattrin, sizeof(setattrin)),
			IOV1(&attrout, sizeof(attrout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_updatenode(fusemount->fnbuf, nodeid, &attrout);
	return 0;
}

int vu_fuse_truncate(const char *pathname, off_t length, int fd, void *fdprivate) {
	(void) fd;
	(void) fdprivate;
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"TRUNCATE path:%s %llu", pathname, length);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, pathname, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	struct fuse_setattr_in setattrin = {
		.valid = FATTR_SIZE,
		.size = length
	};

	struct fuse_attr_out attrout;

	int err = vu_devfuse_conversation(fusemount, FUSE_SETATTR, nodeid,
			IOV1(&setattrin, sizeof(setattrin)),
			IOV1(&attrout, sizeof(attrout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_updatenode(fusemount->fnbuf, nodeid, &attrout);
	return 0;
}

int vu_fuse_symlink(const char *target, const char *linkpath) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"SYMLINK target: %s path:%s", target, linkpath);

	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t dirid;
	int staterr = fuse_lstat(fusemount, linkpath, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(linkpath);
	if (basename == NULL)
		return errno = EINVAL, -1;

	struct fuse_entry_out entryout;

	int err = vu_devfuse_conversation(fusemount, FUSE_SYMLINK, dirid,
			IOV2(basename, strlen(basename) + 1, target, strlen(target) + 1),
			IOV1(&entryout, sizeof(entryout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_add(fusemount->fnbuf, linkpath, &entryout);
	return 0;
}

int vu_fuse_link(const char *oldpath, const char *newpath) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"LINK oldpath: %s newpath:%s", oldpath, newpath);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, oldpath, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	uint64_t dirid;
	staterr = fuse_lstat(fusemount, newpath, &statbuf, &dirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *basename = fuse_basename(newpath);
	if (basename == NULL)
		return errno = EINVAL, -1;

	struct fuse_link_in linkin = {
		.oldnodeid = nodeid
	};
	struct fuse_entry_out entryout;

	int err = vu_devfuse_conversation(fusemount, FUSE_LINK, dirid,
			IOV2(&linkin, sizeof(linkin), basename, strlen(basename) + 1),
			IOV1(&entryout, sizeof(entryout)), NULL);

	if (err < 0)
		return errno = -err, -1;

	fn_add(fusemount->fnbuf, newpath, &entryout);
	return 0;

}

int vu_fuse_rename(const char *oldpath, const char *newpath, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	if (ht == devfuse_ht)
		return vu_devfuse_nosys();
	printkdebug(U,"RENAME oldpath: %s newpath:%s", oldpath, newpath);
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	if (fusemount->mountflags & MS_RDONLY)
		return errno = EROFS, -1;
	struct vu_stat statbuf;

	uint64_t nodeid;
	int staterr = fuse_lstat(fusemount, oldpath, &statbuf, &nodeid, LSTAT_THIS);
	if (staterr < 0)
		return -1;

	uint64_t olddirid;
	staterr = fuse_lstat(fusemount, oldpath, &statbuf, &olddirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	uint64_t newdirid;
	staterr = fuse_lstat(fusemount, newpath, &statbuf, &newdirid, LSTAT_PARENT);
	if (staterr < 0)
		return -1;

	const char *oldbasename = fuse_basename(oldpath);
	if (oldbasename == NULL)
		return errno = EINVAL, -1;

	const char *newbasename = fuse_basename(newpath);
	if (newbasename == NULL)
		return errno = EINVAL, -1;

	int err;
	if (fusemount->initdata.minor < 23) {
		struct fuse_rename_in renamein = {
			.newdir = newdirid
		};
		err = vu_devfuse_conversation(fusemount, FUSE_RENAME, olddirid,
				IOV3(&renamein, sizeof(renamein),
					oldbasename, strlen(oldbasename) + 1,
					newbasename, strlen(newbasename) + 1),
				IOV0, NULL);
	} else {
		struct fuse_rename2_in renamein = {
			.newdir = newdirid,
			.flags = flags
		};
		err = vu_devfuse_conversation(fusemount, FUSE_RENAME2, olddirid,
				IOV3(&renamein, sizeof(renamein),
					oldbasename, strlen(oldbasename) + 1,
					newbasename, strlen(newbasename) + 1),
				IOV0, NULL);
	}

	if (err < 0)
		return errno = -err, -1;

	uint64_t nlookup;
	if (fn_delnode(fusemount->fnbuf, nodeid, &nlookup) > 0) {
		struct fuse_forget_in forgetin = {
			.nlookup = nlookup
		};
		vu_devfuse_conversation(fusemount, FUSE_FORGET, nodeid,
				IOV1(&forgetin, sizeof(forgetin)),
				IOV_NOREPLY, NULL);
	}
	return 0;
}

#if 0
int vu_fuse_ioctl(int fd, unsigned long request, void *buf, uintptr_t addr, void *fdprivate) {
	return vu_devfuse_nosys();
}
#endif
