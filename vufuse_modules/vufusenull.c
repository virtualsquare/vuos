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

int fuse_reentrant_tag = 0;

int op_getattr(const char *path, struct stat *stbuf){
	if (strcmp(path, "/") == 0) {
		memset(stbuf, 0, sizeof(*stbuf));
		stbuf->st_mode = 0755 | S_IFDIR;
		stbuf->st_nlink = 2;
		return 0;
	} else
		return -ENOENT;
}
int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	return 0;
}

static const struct fuse_operations null_ops = {
	.getattr        = op_getattr,
	.readdir        = op_readdir,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &null_ops, NULL);
}
