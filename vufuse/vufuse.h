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

/** Enable merge mode */
#define FUSE_MERGE       (1 << 27)
/** Enable hard remove */
#define FUSE_HARDREMOVE  (1 << 26)

struct fuse {
	void *dlhandle;
	struct fuse_operations fops;

  pthread_t thread;
  pthread_cond_t startloop;
  pthread_cond_t endloop;
  int inuse;
  unsigned long flags;
};

struct main_params {
	int (*pmain)(int argc, char **argv, char** env);
	const char *filesystemtype;
	const char *source;
	const char *target;
	unsigned long *pflags;
	char *opts;
};

struct fileinfo {
  struct fuse_context *context;
  off_t pos;        /* file offset */
  off_t size;       /* file offset */
  struct fuse_file_info ffi;    /* includes open flags, file handle and page_write mode  */
  //struct fuse_node *node;
  struct vudirent *dirinfo;   /* conversion fuse-getdir into kernel compliant dirent. Dir head pointer (list of vudirent) */
  struct vudirent *dirpos;    /* same conversion above: current pos entry (position in the list)*/
};

#endif
