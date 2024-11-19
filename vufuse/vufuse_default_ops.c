/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *                       Leonardo Frioli <leonardo.frioli@studio.unibo.it>
 *   VirtualSquare team.
 *   (inherited from umfuse Copyright 2005 Renzo Davoli)
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

#include <fuse3/fuse.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <vumodule.h>

/* Check fuse.h for the documentation*/

static int vustd_getattr (const char *path, struct stat *stat, struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT getattr %s\n", path);
	return -ENOTSUP;
}

static int vustd_readlink (const char *path, char *link, size_t size)
{
	printkdebug(F,"DEFAULT readlink %s\n", path);
	return -EINVAL;
}

static int vustd_mknod (const char *path, mode_t mode, dev_t dev)
{
	printkdebug(F,"DEFAULT mknod %s\n", path);
	return -ENOSYS;
}

static int vustd_mkdir (const char *path, mode_t mode)
{
	printkdebug(F,"DEFAULT mkdir %s\n", path);
	return -ENOSYS;
}

static int vustd_unlink (const char *path)
{
	printkdebug(F,"DEFAULT unlink %s\n", path);
	return -ENOSYS;
}

static int vustd_rmdir (const char *path)
{
	printkdebug(F,"DEFAULT rmdir %s\n", path);
	return -ENOSYS;
}

static int vustd_symlink (const char *path, const char *newpath)
{
	printkdebug(F,"DEFAULT symlink %s\n", path);
	return -ENOSYS;
}

static int vustd_rename (const char *path, const char *newpath, unsigned int flags)
{
	printkdebug(F,"DEFAULT rename %s\n", path);
	return -ENOSYS;
}

static int vustd_link (const char *path, const char *newpath)
{
	printkdebug(F,"DEFAULT link %s\n", path);
	return -ENOSYS;
}

static int vustd_chmod (const char *path, mode_t mode, struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT chmod %s\n", path);
	return -ENOSYS;
}

static int vustd_chown (const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT chown %s\n", path);
	return -ENOSYS;
}

static int vustd_truncate (const char *path, off_t off, struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT truncat %s\n", path);
	return -ENOSYS;
}

static int vustd_open (const char *path, struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT open %s\n", path);
	return -ENOSYS;
}

static int vustd_read (const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT read %s\n", path);
	return -ENOSYS;
}

static int vustd_write (const char *path, const char *buf, size_t size, off_t off,
		struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT write %s\n", path);
	return -ENOSYS;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 */
#if ( FUSE_MINOR_VERSION >= 5 )
static int vustd_statfs (const char *path, struct statvfs *stat)
#else
static int vustd_statfs (const char *path, struct statfs *stat)
#endif
{
	printkdebug(F,"DEFAULT statfs %s\n", path);
	return -ENOSYS;
}


static int vustd_flush (const char *path, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT flush %s\n", path);
	return 0; //maybe flush is not relevant
}

static int vustd_release (const char *path, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT release %s\n", path);
	return 0;
}

static int vustd_fsync (const char *path, int flags, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT fsync %s\n", path);
	return 0;
}

/** Set extended attributes */
static int vustd_setxattr (const char *path, const char *name, const char *attr, size_t size, int flags)
{
	printkdebug(F,"DEFAULT setxattr %s\n", path);
	return -ENOSYS;
}

/** Get extended attributes */
static int vustd_getxattr (const char *path, const char *name, char *attr, size_t size)
{
	printkdebug(F,"DEFAULT getxattr %s\n", path);
	return -ENOSYS;
}

static int vustd_listxattr (const char *path, char *addrlist, size_t size)
{
	printkdebug(F,"DEFAULT listxattr %s\n", path);
	return -ENOSYS;
}

static int vustd_removexattr (const char *path, const char *name)
{
	printkdebug(F,"DEFAULT removexattr %s\n", path);
	return -ENOSYS;
}

static int vustd_opendir (const char *path, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT opendir %s\n", path);
	return 0;
}

static int vustd_releasedir (const char *path, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT removexattr %s\n", path);
	return 0;
}

static int vustd_fsyncdir (const char *path, int user_meta, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT fsyncdir %s\n", path);
	return -ENOSYS;
}


static int vustd_access (const char *path, int mode)
{
	printkdebug(F,"DEFAULT access %s\n", path);
	return -ENOSYS;
}

static int vustd_create (const char *path, mode_t mode, struct fuse_file_info *fileinfo)
{
	printkdebug(F,"DEFAULT create %s\n", path);
	return -ENOSYS;
}

static int vustd_lock (const char *path, struct fuse_file_info *fileinfo, int cmd, struct flock *fl)
{
	printkdebug(F,"DEFAULT lock %s\n", path);
	return -ENOSYS;
}

static int vustd_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi)
{
	printkdebug(F,"DEFAULT utimens %s\n", path);
	return -ENOSYS;
}

static int vustd_bmap (const char *path, size_t blocksize, uint64_t *idx)
{
	printkdebug(F,"DEFAULT bmap %s\n", path);
	return -ENOSYS;
}

struct fuse_operations vufuse_default_ops = {
	.getattr = vustd_getattr,
	.readlink = vustd_readlink,
	.mknod = vustd_mknod,
	.mkdir = vustd_mkdir,
	.unlink = vustd_unlink,
	.rmdir = vustd_rmdir,
	.symlink = vustd_symlink,
	.rename = vustd_rename,
	.link = vustd_link,
	.chmod = vustd_chmod,
	.chown = vustd_chown,
	.truncate = vustd_truncate,
	.open = vustd_open,
	.read = vustd_read,
	.write = vustd_write,
	.statfs = vustd_statfs,
	.flush = vustd_flush,
	.release = vustd_release,
	.fsync = vustd_fsync,
	.setxattr = vustd_setxattr,
	.getxattr = vustd_getxattr,
	.listxattr = vustd_listxattr,
	.removexattr = vustd_removexattr,
	.opendir = vustd_opendir,
	.releasedir = vustd_releasedir,
	.fsyncdir = vustd_fsyncdir,

	.init = NULL,
	.destroy = NULL,

	.access = vustd_access,
	.create = vustd_create,
	.lock = vustd_lock,
	.utimens = vustd_utimens,
	.bmap = vustd_bmap,
};
