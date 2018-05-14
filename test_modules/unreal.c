/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include <vumodule.h>
#include <errno.h>

VU_PROTOTYPES(unreal)

	struct vu_module_t vu_module = {
		.name = "unreal",
		.description = "Mapping to FS (server side)"
	};

int vu_unreal_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *private) {
	return syscall(__NR_getdents64, fd, dirp, count);
}

int vu_unreal_access(char *path, int mode, int flags) {
	return faccessat(AT_FDCWD, path, mode, flags);
}

static struct vuht_entry_t *ht1,*ht2;

void vu_unreal_cleanup(uint8_t type, void *arg, int arglen,
    struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
		//printk("%*.*s\n", arglen, arglen, arg);
	}
}

void *vu_unreal_init(void) {
	struct vu_service_t *s = vu_mod_getservice();

	vu_syscall_handler(s, lstat) = lstat;
	vu_syscall_handler(s, readlink) = readlink;
	vu_syscall_handler(s, open) = open;
	vu_syscall_handler(s, unlink) = unlink;
	vu_syscall_handler(s, mkdir) = mkdir;
	vu_syscall_handler(s, rmdir) = rmdir;
	vu_syscall_handler(s, mknod) = mknod;
	vu_syscall_handler(s, chmod) = chmod;
	vu_syscall_handler(s, lchown) = lchown;
	vu_syscall_handler(s, utimensat) = utimensat;
	vu_syscall_handler(s, symlink) = symlink;
	vu_syscall_handler(s, link) = link;
	vu_syscall_handler(s, rename) = rename;
	vu_syscall_handler(s, truncate) = truncate;
	vu_syscall_handler(s, statfs) = statfs;
	vu_syscall_handler(s, lgetxattr) = lgetxattr;
	vu_syscall_handler(s, lsetxattr) = lsetxattr;
	vu_syscall_handler(s, llistxattr) = llistxattr;

	vu_syscall_handler(s, close) = close;
	vu_syscall_handler(s, read) = read;
	vu_syscall_handler(s, write) = write;
	vu_syscall_handler(s, lseek) = lseek;
	vu_syscall_handler(s, pread64) = pread;
	vu_syscall_handler(s, pwrite64) = pwrite;
	vu_syscall_handler(s, fcntl) = fcntl;

	ht1 = vuht_pathadd(CHECKPATH,"/","/unreal","unreal",0,"",s,0,NULL,NULL);
	ht2 = vuht_pathadd(CHECKPATH,"/","/unreal","unreal",0,"",s,0,NULL,NULL);

	return NULL;
}

int vu_unreal_fini(void *private) {
	if (ht2 && vuht_del(ht2, MNT_FORCE) == 0)
		ht2 = NULL;
	if (ht1 && vuht_del(ht1, MNT_FORCE) == 0)
		ht1 = NULL;
	return 0;
}
