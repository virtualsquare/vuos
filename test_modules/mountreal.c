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
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <vumodule.h>
#include <errno.h>

VU_PROTOTYPES(mountreal)

	struct vu_module_t vu_module = {
		.name = "mountreal",
		.description = "Mount mapping to FS (server side)"
	};

struct mountreal_entry {
	char *source;
};

static const char *unwrap(const char *path, char *buf, size_t size)
{
	struct mountreal_entry *entry = vu_get_ht_private_data();
	snprintf(buf, size, "%s%s", entry->source, path);
	if (buf[0] == 0)
		snprintf(buf, size, "/");
	// printk("unwrap *%s* -> *%s*\n", path, buf);
	return (buf);
}

int vu_mountreal_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	char pathbuf[PATH_MAX];
	return lstat(unwrap(pathname, pathbuf, PATH_MAX), buf);
}

ssize_t vu_mountreal_readlink(char *path, char *buf, size_t bufsiz) {
	char pathbuf[PATH_MAX];
	return readlink(unwrap(path, pathbuf, PATH_MAX), buf, bufsiz);
}

#if 0
int vu_mountreal_access(char *path, int mode, int flags) {
	char pathbuf[PATH_MAX];
	return faccessat(AT_FDCWD, unwrap(path, pathbuf, PATH_MAX), mode, flags);
}
#endif

int vu_mountreal_open(const char *pathname, int flags, mode_t mode, void **private) {
	char pathbuf[PATH_MAX];
	return open(unwrap(pathname, pathbuf, PATH_MAX), flags, mode);
}

int vu_mountreal_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *private) {
	return syscall(__NR_getdents64, fd, dirp, count);
}

int vu_mountreal_unlink(const char *pathname) {
	char pathbuf[PATH_MAX];
	return unlink(unwrap(pathname, pathbuf, PATH_MAX));
}

int vu_mountreal_mkdir(const char *pathname, mode_t mode) {
	char pathbuf[PATH_MAX];
	return mkdir(unwrap(pathname, pathbuf, PATH_MAX), mode);
}

int vu_mountreal_rmdir(const char *pathname) {
	char pathbuf[PATH_MAX];
	return rmdir(unwrap(pathname, pathbuf, PATH_MAX));
}

int vu_mountreal_mknod(const char *pathname, mode_t mode, dev_t dev) {
	char pathbuf[PATH_MAX];
	return mknod(unwrap(pathname, pathbuf, PATH_MAX), mode, dev);
}

int vu_mountreal_chmod(const char *pathname, mode_t mode, int fd, void *private) {
	char pathbuf[PATH_MAX];
	return chmod(unwrap(pathname, pathbuf, PATH_MAX), mode);
}

int vu_mountreal_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *private) {
	char pathbuf[PATH_MAX];
	return lchown(unwrap(pathname, pathbuf, PATH_MAX), owner, group);
}

int vu_mountreal_utimensat(int dirfd, const char *pathname,
		const struct timespec times[2], int flags, int fd, void *private) {
	char pathbuf[PATH_MAX];
	return utimensat(dirfd, unwrap(pathname, pathbuf, PATH_MAX), times, flags);
}

int vu_mountreal_symlink(const char *target, const char *linkpath) {
	char pathbuf[PATH_MAX];
	return symlink(target, unwrap(linkpath, pathbuf, PATH_MAX));
}

int vu_mountreal_link(const char *target, const char *linkpath) {
	char pathbuf[PATH_MAX];
	char pathbuf2[PATH_MAX];
	return link(unwrap(target, pathbuf, PATH_MAX), unwrap(linkpath, pathbuf2, PATH_MAX));
}

int vu_mountreal_rename(const char *target, const char *linkpath, int flags) {
	char pathbuf[PATH_MAX];
	char pathbuf2[PATH_MAX];
	return rename(unwrap(target, pathbuf, PATH_MAX), unwrap(linkpath, pathbuf2, PATH_MAX));
}

int vu_mountreal_truncate(const char *path, off_t length, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return truncate(unwrap(path, pathbuf, PATH_MAX), length);
}

int vu_mountreal_statfs(const char *path, struct statfs *buf, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return statfs(unwrap(path, pathbuf, PATH_MAX), buf);
}

ssize_t vu_mountreal_lgetxattr(const char *path, const char *name,
		void *value, size_t size, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return lgetxattr(unwrap(path, pathbuf, PATH_MAX), name, value, size);
}

int vu_mountreal_lsetxattr(const char *path, const char *name,
		const void *value, size_t size, int flags, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return lsetxattr(unwrap(path, pathbuf, PATH_MAX), name, value, size, flags);
}

ssize_t vu_mountreal_llistxattr(const char *path,
		char *list, size_t size, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return llistxattr(unwrap(path, pathbuf, PATH_MAX), list, size);
}

int vu_mountreal_lremovexattr(const char *path, const char *name, int fd, void *fdprivate) {
	char pathbuf[PATH_MAX];
	return lremovexattr(unwrap(path, pathbuf, PATH_MAX), name);
}

int vu_mountreal_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	struct mountreal_entry *entry = malloc(sizeof(struct mountreal_entry));
	const char *source_no_root = strcmp(source, "/") == 0 ? "" : source;
	//printk("MOUNT %s %s\n", source, target);
	entry->source = strdup(source_no_root);
	vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, entry);
	errno = 0;
	return 0;
}

int vu_mountreal_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	int ret_value;
	if ((ret_value = vuht_del(ht, flags)) < 0) {
		errno = -ret_value;
		return -1;
	}
	return 0;
}

void vu_mountreal_cleanup(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
		struct mountreal_entry *entry = vuht_get_private_data(ht);
		if (entry->source)
			free(entry->source);
		free(entry);
	}
}

void *vu_mountreal_init(void) {
	struct vu_service_t *s = vu_mod_getservice();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, close) = close;
	vu_syscall_handler(s, read) = read;
	vu_syscall_handler(s, write) = write;
	vu_syscall_handler(s, lseek) = lseek;
	vu_syscall_handler(s, pread64) = pread;
	vu_syscall_handler(s, pwrite64) = pwrite;
	vu_syscall_handler(s, fcntl) = fcntl;
	vu_syscall_handler(s, epoll_ctl) = epoll_ctl;
#pragma GCC diagnostic pop

	return NULL;
}

int vu_mountreal_fini(void *private) {
	return 0;
}
