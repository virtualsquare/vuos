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

#ifndef VUFUSE_H
#define VUFUSE_H
#include <fuse.h>

#ifndef VUFUSE_FUSE_VERSION
#define VUFUSE_FUSE_VERSION 29
#endif

/** Enable hard remove */
#define FUSE_HARDREMOVE  (1 << 0)

struct fuse {
	void *dlhandle;
	struct fuse_operations fops;

	pthread_mutex_t mutex;

	pthread_t thread;
	pthread_cond_t startloop;
	pthread_cond_t endloop;

	int inuse;
	int fake_chan_fd;
	unsigned long mountflags;
	unsigned long fuseflags;
	void *private_data;
};

struct fileinfo {
	//char *path;
	struct fuse_node *node;
	off_t pos;        /* file offset */
	struct fuse_file_info ffi;    /* includes open flags, file handle and page_write mode  */
	FILE *dirf;
};

struct fuse_context *fuse_push_context(struct fuse_context *new);
void fuse_pop_context(struct fuse_context *old);

#endif
