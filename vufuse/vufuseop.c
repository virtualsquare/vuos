/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *                       Leonardo Frioli <leonardo.frioli@studio.unibo.it>
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/sysmacros.h>
#include <fuse.h>
#include <volatilestream.h>
#include <vumodule.h>
#include <vufuse_node.h>
#include <vufuse.h>

VU_PROTOTYPES(vufuse)

#define FILEPATH(x) vufuse_node_path(x->node)

/*heuristics for file system which does not set st_ino */
static inline unsigned long hash_inodeno (const char *s) {
	unsigned long sum = 0;
	while (*s) {
		sum = sum ^ ((sum << 5) + (sum >> 2) + *s);
		s++;
	}
	return sum;
}

/* (vufuse_get_filesize callers need to hold the mutex */
static off_t vufuse_get_filesize(char *pathname) {
	struct fuse *fuse = vu_get_ht_private_data();
	struct vu_stat buf;
	int rv;
	memset(&buf, 0, sizeof(struct vu_stat));
	rv	= fuse->fops.getattr(pathname, &buf);
	return (rv >= 0) ? buf.st_size : 0;
}

int vu_vufuse_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);
	pthread_mutex_lock(&(fc.fuse->mutex));

	memset(buf, 0, sizeof(struct vu_stat));
	rv = fc.fuse->fops.getattr(pathname, buf);
	fuse_pop_context(ofc);

	pthread_mutex_unlock(&(fc.fuse->mutex));
	printkdebug(F,"LSTAT path:%s retvalue:%d", pathname, rv);

	if (rv < 0) {
		errno = -rv;
		return -1;
	} else {
		/*heuristics for file system which does not set st_ino */
		if (buf->st_ino == 0)
			buf->st_ino = (ino_t) hash_inodeno(pathname);
		/*heuristics for file system which does not set st_dev */
		if (buf->st_dev == 0)
			buf->st_dev = (dev_t)((unsigned long) fc.fuse);
	}
	return rv;
}

int vu_vufuse_access(char *path, int mode, int flags) {
	int rv = 0;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);
	pthread_mutex_lock(&(fc.fuse->mutex));

	/* "default permission" management */
	rv = fc.fuse->fops.access(path, mode);
	if (rv == -ENOSYS) {
		struct vu_stat buf;
		rv = fc.fuse->fops.getattr(path, &buf);
	}
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"ACCESS path:%s mode:%s%s%s%s retvalue:%d",path,
			(mode & R_OK) ? "R_OK": "", (mode & W_OK) ? "W_OK": "",
			(mode & X_OK) ? "X_OK": "", (mode & F_OK) ? "F_OK": "",
			rv);

	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

ssize_t vu_vufuse_readlink(char *path, char *buf, size_t bufsiz) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.readlink(path, buf, bufsiz);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	if (rv == 0)
		rv = strnlen(buf,bufsiz);
	fuse_pop_context(ofc);

	printkdebug(F,"READLINK path:%s buf:%s retvalue:%zd",path,buf,rv);

	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

#define FUSE_SUPER_MAGIC 0x65735546
int vu_vufuse_statfs (const char *pathname, struct statfs *buf, int fd, void *fdprivate) {
	struct fuse_context fc, *ofc;
	int rv;
	struct statvfs svfs;
	ofc = fuse_push_context(&fc);
	printkdebug(F,"STATFS", NULL);
	pthread_mutex_lock(&(fc.fuse->mutex));
	memset (&svfs, 0, sizeof(struct statvfs));
	rv = fc.fuse->fops.statfs(pathname, &svfs);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));
	if (rv >= 0) {
		buf->f_type = FUSE_SUPER_MAGIC; //
		buf->f_bsize = svfs.f_bsize;
		buf->f_blocks = svfs.f_blocks;
		buf->f_bfree = svfs.f_bfree;
		buf->f_bavail = svfs.f_bavail;
		buf->f_files = svfs.f_files;
		buf->f_ffree = svfs.f_ffree;
		buf->f_namelen =svfs.f_namemax;
		buf->f_frsize =svfs.f_frsize;
		/* fsid is left zero */
		return rv;
	} else {
		errno = -rv;
		return -1;
	}
}

int vu_vufuse_mkdir (const char *pathname, mode_t mode) {
	int rv = 0;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.mkdir(pathname, mode);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"MKDIR path:%s retvalue:%d",pathname,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_mknod (const char *pathname, mode_t mode, dev_t dev)
{
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	if (S_ISREG(mode)) {
		struct fuse_file_info fi;
		memset(&fi, 0, sizeof(fi));
		fi.flags = O_CREAT | O_EXCL | O_WRONLY;
		rv = fc.fuse->fops.create(pathname, mode, &fi);
		if (rv >= 0) {
			fc.fuse->fops.release(pathname, &fi);
		} else if (rv == -ENOSYS)
			rv = fc.fuse->fops.mknod(pathname, mode, dev);
	} else
		rv = fc.fuse->fops.mknod(pathname, mode, dev);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"MKNOD path:%s major:%d minor:%d  retvalue:%d",pathname,major(dev),minor(dev),rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_rmdir(const char *pathname) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.rmdir( pathname);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"RMDIR path:%s retvalue:%d",pathname,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}


int vu_vufuse_chmod (const char *pathname, mode_t mode, int fd, void *fdprivate) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.chmod(pathname, mode);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"CHMOD path:%s retvalue:%d",pathname,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_lchown (const char *pathname, uid_t owner, gid_t group,int fd, void *fdprivate) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.chown(pathname, owner, group);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"LCHOWN  retvalue:%d",rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_symlink (const char *target, const char *linkpath) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.symlink( target, linkpath);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"SYMLINK target:%s linkpath:%s retvalue:%d",target,linkpath,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_truncate(const char *path, off_t length, int fd, void *fdprivate) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.truncate(path, length);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"TRUNCATE path:%s retvalue:%d",path,rv);

	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_link (const char *target, const char *linkpath) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	rv = fc.fuse->fops.link(target, linkpath);
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"LINK oldpath:%s newpath:%s retvalue:%d",target,linkpath,rv);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_open(const char *pathname, int flags, mode_t mode, void **private) {
	int rv;
	int exists_err;
	struct fileinfo *ft;
	struct vu_stat buf;

	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);
	pthread_mutex_lock(&(fc.fuse->mutex));

	exists_err = fc.fuse->fops.getattr(pathname, &buf); /* if 0 the file already exists.*/

	if ((flags & O_ACCMODE) != O_RDONLY && fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		pthread_mutex_unlock(&(fc.fuse->mutex));
		return -1;
	}

	if ( (flags & (O_DIRECTORY)) && (!S_ISDIR(buf.st_mode))) {
		fuse_pop_context(ofc);
		errno = ENOTDIR;
		pthread_mutex_unlock(&(fc.fuse->mutex));
		return -1;
	}

	if ((flags & O_ACCMODE) != O_RDONLY && (S_ISDIR(buf.st_mode))) {
		fuse_pop_context(ofc);
		errno = EISDIR;
		pthread_mutex_unlock(&(fc.fuse->mutex));
		return -1;
	}

	if (exists_err == 0) { /* the file exists*/
		if ((flags & O_CREAT) && (flags & O_EXCL)) {
			errno = EEXIST;
			pthread_mutex_unlock(&(fc.fuse->mutex));
			return -1;
		}

		if ((flags & O_TRUNC) && (flags & O_ACCMODE)!= O_RDONLY) {
			rv = fc.fuse->fops.truncate(pathname, 0);

			printkdebug(F,"TRUNCATE path:%s flags:%x retvalue:%d",pathname,flags,rv);
			if (rv < 0) {
				fuse_pop_context(ofc);
				pthread_mutex_unlock(&(fc.fuse->mutex));
				errno = -rv;
				return -1;
			}
		}
	}

	ft = malloc(sizeof(struct fileinfo));
	ft->pos = 0;
	ft->ffi.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	ft->ffi.writepage = 0;
	ft->node = NULL;
	ft->dirf = NULL;

	*private = NULL;

	/* create the file: create or (obsolete mode) mknod+open */
	if ((flags & O_CREAT) && (exists_err != 0)) {

		rv = fc.fuse->fops.create(pathname, S_IFREG | mode, &ft->ffi);

		if (rv == -ENOSYS) {
			rv = fc.fuse->fops.mknod(pathname, S_IFREG | mode, (dev_t) 0);

			printkdebug(F,"MKNOD path:%s flags:%x retvalue:%d",pathname,flags,rv);
			if (rv < 0) {
				fuse_pop_context(ofc);
				free(ft);
				errno = -rv;
				pthread_mutex_unlock(&(fc.fuse->mutex));
				return -1;
			}
			rv = fc.fuse->fops.open(pathname, &ft->ffi);
		} else {
			printkdebug(F,"CREATE path:%s flags:%x retvalue:%d",pathname,flags,rv);
		}

#if 0
		/* this should be useless */
		if (rv >= 0) {
			if (fc.fuse->fops.fgetattr != NULL)
				rv = fc.fuse->fops.fgetattr(pathname, &buf, &ft->ffi);
			else
				rv = fc.fuse->fops.getattr(pathname, &buf);
		}
#endif

	} else { /* the file exists! */
		if (flags & O_DIRECTORY && fc.fuse->fops.readdir != NULL) {
			rv = fc.fuse->fops.opendir(pathname, &ft->ffi);
			if (rv == -ENOSYS)
				rv = fc.fuse->fops.open(pathname, &ft->ffi);
		} else
			rv = fc.fuse->fops.open(pathname, &ft->ffi);
	}
	fuse_pop_context(ofc);
	pthread_mutex_unlock(&(fc.fuse->mutex));

	printkdebug(F,"OPEN path:%s flags:%x retvalue:%d",pathname,flags,rv);
	if (rv < 0) {
		free(ft);
		errno = -rv;
		return -1;
	} else {
		ft->node = vufuse_node_add(fc.fuse, pathname);
		fc.fuse->inuse++;
		*private = ft;
		/*file related function will check sfd >= 0 before accessing fdprivate. That sfd will have the value of rv, so returning 0 is ok*/
		return rv;
	}
}

int vu_vufuse_close(int fd, void *fdprivate) {
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		int rv;
		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		struct fuse_context fc, *ofc;
		ofc = fuse_push_context(&fc);
		pthread_mutex_lock(&(fc.fuse->mutex));

		if (!(ft->ffi.flags & O_DIRECTORY)) {
			rv = fc.fuse->fops.flush(FILEPATH(ft), &ft->ffi);
		}

		fc.fuse->inuse--;
		if ((ft->ffi.flags & O_DIRECTORY) && fc.fuse->fops.readdir != NULL) {
			rv = fc.fuse->fops.releasedir(FILEPATH(ft), &ft->ffi);
		} else
			rv = fc.fuse->fops.release(FILEPATH(ft), &ft->ffi);

		if (rv >= 0) {
			char *hiddenfile = vufuse_node_del(ft->node);
			if (hiddenfile) {
				fc.fuse->fops.unlink(hiddenfile);
				free(hiddenfile);
			}
		}

		fuse_pop_context(ofc);
		pthread_mutex_unlock(&(fc.fuse->mutex));
		printkdebug(F,"CLOSE retvalue:%d", rv);

		if (rv < 0) {
			errno = -rv;
			return -1;
		} else {
			if (ft->dirf)
				fclose(ft->dirf);
			free(fdprivate);
			fdprivate = NULL;
			return rv;
		}
	}
}

off_t vu_vufuse_lseek(int fd, off_t offset, int whence, void *fdprivate)
{
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		struct fileinfo *ft =(struct fileinfo *)fdprivate;
		struct fuse *fuse = vu_get_ht_private_data();

		printkdebug(F,"LSEEK path:%s offset:%jd whence:%d", FILEPATH(ft), (intmax_t)offset, whence);
		pthread_mutex_lock(&(fuse->mutex));
		switch (whence) {
			case SEEK_SET:
				ft->pos = offset;
				break;
			case SEEK_CUR:
				ft->pos += offset;
				break;
			case SEEK_END:
				ft->pos = vufuse_get_filesize(FILEPATH(ft)) + offset;
		}
		pthread_mutex_unlock(&(fuse->mutex));
		return ft->pos;
	}
}

ssize_t vu_vufuse_read (int fd, void *buf, size_t count, void *fdprivate) {
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		int rv;
		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		if ((ft->ffi.flags & O_ACCMODE) == O_WRONLY) {
			errno = EBADF;
			return -1;
		} else {
			struct fuse_context fc, *ofc;
			ofc = fuse_push_context(&fc);
			pthread_mutex_lock(&(fc.fuse->mutex));
			rv = fc.fuse->fops.read(FILEPATH(ft), buf, count, ft->pos, &ft->ffi);
			fuse_pop_context(ofc);
			if (rv >= 0)
				ft->pos += rv;
			pthread_mutex_unlock(&(fc.fuse->mutex));

			printkdebug(F,"READ path:%s count:%u retvalue:%zd",FILEPATH(ft), count,rv);
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;
		}
	}
}

ssize_t vu_vufuse_pread64 (int fd, void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		int rv;
		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		if ((ft->ffi.flags & O_ACCMODE) == O_WRONLY) {
			errno = EBADF;
			return -1;
		} else {
			struct fuse_context fc, *ofc;
			ofc = fuse_push_context(&fc);
			pthread_mutex_lock(&(fc.fuse->mutex));
			rv = fc.fuse->fops.read(FILEPATH(ft), buf, count, offset, &ft->ffi);
			fuse_pop_context(ofc);
			pthread_mutex_unlock(&(fc.fuse->mutex));

			printkdebug(F,"PREAD64 path:%s count:%u offset:%jd retvalue:%zd",FILEPATH(ft), count,
					(intmax_t) offset, rv);
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;
		}
	}
}

ssize_t vu_vufuse_write(int fd, const void *buf, size_t count, void *fdprivate) {
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		int rv = 0;

		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		if ((ft->ffi.flags & O_ACCMODE) == O_RDONLY) {
			errno = EBADF;
			return -1;
		} else {
			struct fuse_context fc, *ofc;
			ofc = fuse_push_context(&fc);
			pthread_mutex_lock(&(fc.fuse->mutex));
			if (ft->ffi.flags & O_APPEND)
				ft->pos = vufuse_get_filesize(FILEPATH(ft));
			rv = fc.fuse->fops.write(FILEPATH(ft), buf, count, ft->pos, &ft->ffi);
			fuse_pop_context(ofc);

			if (rv >= 0)
				ft->pos += rv;
			pthread_mutex_unlock(&(fc.fuse->mutex));

			printkdebug(F,"WRITE path:%s count:%x retvalue:%d",FILEPATH(ft),count, rv);
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;
		}
	}
}

ssize_t vu_vufuse_pwrite64(int fd, const void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	if (fd < 0 || fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		int rv = 0;

		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		if ((ft->ffi.flags & O_ACCMODE) == O_RDONLY) {
			errno = EBADF;
			return -1;
		} else {
			struct fuse_context fc, *ofc;
			ofc = fuse_push_context(&fc);
			pthread_mutex_lock(&(fc.fuse->mutex));
			rv = fc.fuse->fops.write(FILEPATH(ft), buf, count, offset, &ft->ffi);
			fuse_pop_context(ofc);
			pthread_mutex_unlock(&(fc.fuse->mutex));

			printkdebug(F,"PWRITE64 path:%s count:%x offset:%jd retvalue:%zd", FILEPATH(ft), count, rv);
			if (rv < 0) {
				errno = -rv;
				return -1;
			} else
				return rv;
		}
	}
}

static int vufuse_common_filldir(FILE *f, const char *name, unsigned char type, __ino64_t ino) {
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

/* Function to add an entry in a readdir() operation */
static int vufusefillreaddir(void *buf, const char *name, const struct stat *stbuf, off_t off) {
	FILE *f = buf;
	__ino64_t d_ino;
	unsigned char d_type;
	if (stbuf == NULL) {
		d_ino = -1;
		d_type = 0;
	} else {
		d_ino = stbuf->st_ino;
		d_type = stbuf->st_mode >> 12;
	}
	return vufuse_common_filldir(f, name, d_type, d_ino);
}

struct fuse_dirhandle {
	FILE *f;
};

static int vufusefilldir(fuse_dirh_t h, const char *name, int type, ino_t ino) {
	return vufuse_common_filldir(h->f, name, type, ino);
}

int vu_vufuse_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate) {
	if (fdprivate == NULL) {
		errno = EBADF;
		return -1;
	} else {
		struct fileinfo *ft = (struct fileinfo *)fdprivate;
		struct fuse *fuse = vu_get_ht_private_data();
		size_t freadout;
		printkdebug(F,"GETDENTS", NULL);

		if (ft->dirf == NULL) {
			int rv;
			struct fuse_context fc, *ofc;
			ofc = fuse_push_context(&fc);
			pthread_mutex_lock(&(fc.fuse->mutex));
			ft->dirf = volstream_open();
			if (fc.fuse->fops.readdir != NULL)
				rv = fc.fuse->fops.readdir(FILEPATH(ft), ft->dirf, vufusefillreaddir, 0, &ft->ffi);
			else {
				struct fuse_dirhandle dh = {.f = ft->dirf};
				rv = fc.fuse->fops.getdir(FILEPATH(ft), &dh, vufusefilldir);
			}
			fuse_pop_context(ofc);
			pthread_mutex_unlock(&(fc.fuse->mutex));
			if (rv < 0) {
				fclose(ft->dirf);
				return 0;
			} else
				fseek(ft->dirf, 0, SEEK_SET);
		}

		pthread_mutex_lock(&(fuse->mutex));
		freadout = fread(dirp, 1, count, ft->dirf);
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
				fseeko(ft->dirf, - (int) (count - bpos), SEEK_CUR);
				freadout -= count - bpos;
			}
			/* the buffer is so short that it does not fit one
				 entry. Return EINVAL! */
			if (freadout == 0) {
				pthread_mutex_unlock(&(fuse->mutex));
				errno = EINVAL;
				return -1;
			}
		}
		pthread_mutex_unlock(&(fuse->mutex));
		return freadout;
	}
}

int vu_vufuse_unlink (const char *pathname) {
	int rv;
	struct fuse_context fc, *ofc;
	struct vu_stat buf;
	ofc = fuse_push_context(&fc);
	char *hiddenpath = NULL;

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	if (fc.fuse->fops.getattr(pathname, &buf) < 0) {
		pthread_mutex_unlock(&(fc.fuse->mutex));
		fuse_pop_context(ofc);
		errno = ENOENT;
		return -1;
	}

	if (fc.fuse->fuseflags & FUSE_HARDREMOVE || (hiddenpath = vufuse_node_rename(fc.fuse, pathname, NULL)) == NULL ||
			(rv = fc.fuse->fops.rename(pathname,hiddenpath)) < 0) {
		if (hiddenpath)
			vufuse_node_rename(fc.fuse, hiddenpath, pathname);

		rv = fc.fuse->fops.unlink(pathname);

		pthread_mutex_unlock(&(fc.fuse->mutex));
		printkdebug(F,"UNLINK path:%s retvalue:%d",pathname, rv);
	} else {

		pthread_mutex_unlock(&(fc.fuse->mutex));
		printkdebug(F,"RENAME(UNLINK) path:%s hiddenpath:%s retvalue:%d",pathname,hiddenpath,rv);
	}

	fuse_pop_context(ofc);
	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}

int vu_vufuse_rename (const char *target, const char *linkpath, int flags) {
	int rv;
	struct fuse_context fc, *ofc;
	ofc = fuse_push_context(&fc);
	char *hiddenpath = NULL;

	if (fc.fuse->mountflags & MS_RDONLY) {
		fuse_pop_context(ofc);
		errno = EROFS;
		return -1;
	}

	pthread_mutex_lock(&(fc.fuse->mutex));
	if (fc.fuse->fuseflags & FUSE_HARDREMOVE || (hiddenpath = vufuse_node_rename(fc.fuse, linkpath, NULL)) == NULL ||
			fc.fuse->fops.rename(linkpath,hiddenpath) < 0) {
		if (hiddenpath) {
			vufuse_node_rename(fc.fuse, hiddenpath, linkpath);
			hiddenpath = NULL;
		}
	}

	rv = fc.fuse->fops.rename(target,linkpath);

	if (rv >= 0)
		vufuse_node_rename(fc.fuse, target, linkpath);
	else if (hiddenpath) {
		// revert the renaming to hiddenpath
		if (fc.fuse->fops.rename(hiddenpath, linkpath) >= 0)
			vufuse_node_rename(fc.fuse, hiddenpath, linkpath);
	}
	pthread_mutex_unlock(&(fc.fuse->mutex));
	fuse_pop_context(ofc);

	printkdebug(F,"RENAME oldpath:%s newpath:%s retvalue:%d",target,linkpath,rv);

	if (rv < 0) {
		errno = -rv;
		return -1;
	} else
		return rv;
}
