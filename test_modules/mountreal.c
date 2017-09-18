#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vumodule.h>
#include <errno.h>

VU_PROTOTYPES(mountreal)

	struct vu_module_t vu_module = {
		.name = "mountreal",
		.description = "/mountreal Mount mapping to FS (server side)"
	};

struct mountreal_entry {
	char *source;
	int targetlen;
};

static const char *unwrap(const char *path, char *buf, size_t size)
{
	struct mountreal_entry *entry = vu_get_ht_private_data();
	const char *tail = path + entry->targetlen;
	if (*tail)
		snprintf(buf, size, "%s%s", entry->source, path + entry->targetlen);
	else
		snprintf(buf, size, "%s/", entry->source);
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

int vu_mountreal_access(char *path, int mode, int flags) {
	char pathbuf[PATH_MAX];
	return access(unwrap(path, pathbuf, PATH_MAX), mode);
}

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

int vu_mountreal_mount(const char *source, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data) {
	//struct vu_service_t *s = vu_module.service;
	struct vu_service_t *s = vu_mod_getservice();
	struct mountreal_entry *entry = malloc(sizeof(struct mountreal_entry));
	const char *source_no_root = strcmp(source, "/") == 0 ? "" : source;
	const char *target_no_root = strcmp(target, "/") == 0 ? "" : target;
	entry->source = strdup(source_no_root);
	entry->targetlen = strlen(target_no_root);
	vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, entry);
	errno = 0;
	return 0;
}

int vu_mountreal_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	struct mountreal_entry *entry = vuht_get_private_data(ht);
	int ret_value;
	if ((ret_value = vuht_del(ht, 1)) < 0) {
		errno = -ret_value;
		return -1;
	}
	if (entry->source)
		free(entry->source);
	free(entry);
	return 0;
}

void *vu_mountreal_init(void) {
	struct vu_service_t *s = vu_mod_getservice();

	vu_syscall_handler(s, close) = close;
	vu_syscall_handler(s, read) = read;
	vu_syscall_handler(s, write) = write;
	vu_syscall_handler(s, lseek) = lseek;

	return NULL;
}

void vu_mountreal_fini(void *private) {
}
