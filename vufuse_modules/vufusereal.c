/**
 * Copyright (c) 2018 Renzo Davoli <renzo@cs.unibo.it>
 *                    Leonardo Frioli <leonardo.frioli@studio.unibo.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the fuse-ext2
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define FUSE_USE_VERSION 29

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fuse.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define GETPATH(source, path) \
	char path ## _fullpath [PATH_MAX]; \
	sprintf( (path ## _fullpath) , "%s%s", (strcmp(source,"/")) ? source : "", path); \
	path = path ## _fullpath

#define RETURN(retvalue) return ((retvalue < 0) ? -errno : retvalue)

#define RETURNZER0(retvalue) return ((retvalue < 0) ? -errno : 0)

void * op_init (struct fuse_conn_info *conn){
	struct fuse_context *cntx=fuse_get_context();
	return cntx->private_data;
}

void op_destroy(void *userdata){
	return;
}

int op_access(const char *path, int mask){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = access(path, mask);

	RETURN(rv);
}

int op_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi){
	int fd = (int) fi->fh;
	int rv = fstat(fd,stbuf);

	RETURN(rv);
}

int op_getattr(const char *path, struct stat *stbuf){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);

	int rv = lstat(path,stbuf);

	RETURN(rv);
}

int op_getxattr(const char *path, const char *name, char *value, size_t size){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = getxattr (path, name, (void *)value, size);

	RETURN(rv);
}

int op_open(const char *path, struct fuse_file_info *fi){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);

	int fd = open(path,fi->flags);
	fi->fh = (uint64_t) fd;

	/*on success open must return 0 otherwise ERANGE is given*/
	RETURNZER0(fd);
}

int op_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	int fd = (int) fi->fh;

	if( lseek(fd,offset,SEEK_SET)< 0) {
		errno = EINVAL;
		return -errno;

	} else {
		int rv = read(fd,buf,size);

		RETURN(rv);
	}
}

int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);

	struct dirent* de;
	DIR * dr = fdopendir((int)fi->fh);


	if(dr == NULL) return -errno;

	while ((de = readdir(dr)) != NULL){
		struct stat stbuf ;
		char filename[PATH_MAX];
		sprintf( filename , "%s%s",(strcmp(path,"/")) ? path : "",de->d_name) ;

		//ignoring offset
		if (lstat(filename, &stbuf) >=  0){
			filler(buf,de->d_name,&stbuf,0);

		} else filler(buf,de->d_name,NULL,0);
		//test for return value 1 ?
	}
	return 0;

}

int op_readlink(const char *path, char *buf, size_t size){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	memset(buf,'\0',size);
	int rv = readlink(path,buf,size);


	RETURNZER0(rv);
}


int op_release(const char *path, struct fuse_file_info *fi){ //close
	int fd = (int) fi->fh;
	fi->fh = (uint64_t) -1; // correct?
	int rv = close(fd);

	RETURN(rv);

}

int op_statfs(const char *path, struct statvfs *buf){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = statvfs(path,buf);

	RETURN(rv);
}

int op_chmod(const char *path, mode_t mode){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = chmod(path,mode);

	RETURN(rv);
}

int op_chown(const char *path, uid_t uid, gid_t gid){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = chown(path,uid,gid);

	RETURN(rv);
}

int op_create(const char *path, mode_t mode, struct fuse_file_info *fi){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int fd = open(path,fi->flags | O_CREAT ,mode);
	fi->fh = (uint64_t) fd;

	RETURNZER0(fd);
}

int op_flush(const char *path, struct fuse_file_info *fi){
	/*
	 * do nothing
	 */
	return 0;
}

int op_fsync(const char *path, int datasync, struct fuse_file_info *fi){
	/*
	 * do nothing
	 */
	return 0;
}

int op_mkdir(const char *path, mode_t mode){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = mkdir(path,mode|S_IFDIR);

	RETURN(rv);
}

int op_rmdir(const char *path){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = rmdir(path);

	RETURN(rv);
}

int op_unlink(const char *path){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = unlink(path);

	RETURN(rv);
}

int op_utimens(const char *path, const struct timespec tv[2]){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);

	int rv = utimensat(-1,path,tv,0);

	RETURN(rv);
}

int op_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	int fd = (int) fi->fh;

	if( lseek(fd,offset,SEEK_SET)< 0) {
		errno = EINVAL;
		return -errno;

	} else {
		int rv =  write(fd,buf,size);

		RETURN(rv);
	}
}

int op_mknod(const char *path, mode_t mode, dev_t dev){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = mknod(path,mode,dev);

	RETURN(rv);
}

int op_symlink(const char *sourcename, const char *destname){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, destname);

	int rv = symlink(sourcename,destname);

	RETURN(rv);
}

int op_truncate(const char *path, off_t length){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, path);
	int rv = truncate(path,length);

	RETURN(rv);
}

int op_ftruncate(const char *path, off_t length, struct fuse_file_info *fi){
	int fd = (int) fi->fh;

	int rv = ftruncate(fd,length);

	RETURN(rv);
}

//only allowed hardlink internal to the mount point
int op_link (const char *source, const char *dest){
	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, source);
	GETPATH(sourcepath, dest);

	int rv =  link(source,dest);

	RETURN(rv);
}

//called only on internal rename
int op_rename(const char *source, const char *dest){

	struct fuse_context *cntx=fuse_get_context();
	char *sourcepath = cntx->private_data;
	GETPATH(sourcepath, source);
	GETPATH(sourcepath, dest);
	int rv =  rename(source,dest);

	RETURN(rv);
}

static const struct fuse_operations real_ops = {
	.getattr        = op_getattr,
	.readlink       = op_readlink,
	.mknod          = op_mknod,
	.mkdir          = op_mkdir,
	.unlink         = op_unlink,
	.rmdir          = op_rmdir,
	.symlink        = op_symlink,
	.rename         = op_rename,
	.link           = op_link,
	.chmod          = op_chmod,
	.chown          = op_chown,
	.truncate       = op_truncate,
	.open           = op_open,
	.read           = op_read,
	.write          = op_write,
	.statfs         = op_statfs,
	.flush          = op_flush,
	.release        = op_release,
	.fsync          = op_fsync,
	.setxattr       = NULL,
	.getxattr       = op_getxattr,
	.listxattr      = NULL,
	.removexattr    = NULL,
	.opendir        = op_open,
	.readdir        = op_readdir,
	.releasedir     = op_release,
	.fsyncdir       = op_fsync,
	.init           = op_init,
	.destroy        = op_destroy,
	.access         = op_access,
	.create         = op_create,
	.ftruncate      = op_ftruncate,
	.fgetattr       = op_fgetattr,
	.lock           = NULL,
	.utimens        = op_utimens,
	.bmap           = NULL,
};

int main(int argc, char *argv[])
{
	int err;
	char *sourcepath = argv[argc-2];
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;

	//printf("version:'%s', fuse_version:'%d / %d / %d'\n", __VERSION__, FUSE_USE_VERSION,  FUSE_VERSION, fuse_version());

	err = fuse_main(argc, argv, &real_ops, sourcepath);

	return err;
}
