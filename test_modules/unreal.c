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
 *   UMDEV: Virtual Device in Userspace
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
		.description = "/unreal Mapping to FS (server side)"
	};

static const char *unwrap(const char *path)
{
	const char *s;
	s = &(path[7]);
	if (*s == 0)
		s = "/";
	return (s);
}

int vu_unreal_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	return lstat(unwrap(pathname), buf);
}

ssize_t vu_unreal_readlink(char *path, char *buf, size_t bufsiz) {
	return readlink(unwrap(path), buf, bufsiz);
}

int vu_unreal_access(char *path, int mode, int flags) {
	return access(unwrap(path), mode);
}

int vu_unreal_open(const char *pathname, int flags, mode_t mode, void **private) {
	return open(unwrap(pathname), flags, mode);
}

int vu_unreal_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *private) {
	return syscall(__NR_getdents64, fd, dirp, count);
}

int vu_unreal_unlink(const char *pathname) {
	return unlink(unwrap(pathname));
}

int vu_unreal_mkdir(const char *pathname, mode_t mode) {
	return mkdir(unwrap(pathname), mode);
}

int vu_unreal_rmdir(const char *pathname) {
	return rmdir(unwrap(pathname));
}

int vu_unreal_chmod(const char *pathname, mode_t mode, int fd, void *private) {
	return chmod(unwrap(pathname), mode);
}

int vu_unreal_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *private) {
	return lchown(unwrap(pathname), owner, group);
}

int vu_unreal_utimensat(int dirfd, const char *pathname,
		const struct timespec times[2], int flags, int fd, void *private) {
	return utimensat(dirfd, unwrap(pathname), times, flags);
}

int vu_unreal_symlink(const char *target, const char *linkpath) {
	return symlink(target, unwrap(linkpath));
}

int vu_unreal_link(const char *target, const char *linkpath) {
	return link(unwrap(target), unwrap(linkpath));
}

int vu_unreal_rename(const char *target, const char *linkpath, int flags) {
	return rename(unwrap(target), unwrap(linkpath));
}

int vu_unreal_truncate(const char *path, off_t length, int fd, void *fdprivate) {
	return truncate(unwrap(path), length);
}

ssize_t vu_unreal_lgetxattr(const char *path, const char *name,
		void *value, size_t size, int fd, void *fdprivate) {
	return lgetxattr(unwrap(path), name, value, size);
}

int vu_unreal_lsetxattr(const char *path, const char *name, 
		const void *value, size_t size, int flags, int fd, void *fdprivate) {
	return lsetxattr(unwrap(path), name, value, size, flags);
}

ssize_t vu_unreal_llistxattr(const char *path,
		char *list, size_t size, int fd, void *fdprivate) {
	return llistxattr(unwrap(path), list, size);
}

int vu_unreal_lremovexattr(const char *path, const char *name, int fd, void *fdprivate) {
	return lremovexattr(unwrap(path), name);
}

static struct vuht_entry_t *ht1,*ht2;

void *vu_unreal_init(void) {
	struct vu_service_t *s = vu_mod_getservice();

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

void vu_unreal_fini(void *private) {
	if (ht2 && vuht_del(ht2, 0) == 0)
		ht2 = NULL;
	if (ht1 && vuht_del(ht1, 0) == 0)
		ht1 = NULL;
}
