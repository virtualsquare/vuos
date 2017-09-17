#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
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

struct twohte {
	struct vuht_entry_t *ht1,*ht2;
};

void *vu_unreal_init(void) {
	struct twohte *two = malloc(sizeof(struct twohte));
	struct vu_service_t *s = vu_module.service;

	vu_syscall_handler(s, close) = close;
	vu_syscall_handler(s, read) = read;
	vu_syscall_handler(s, write) = write;
	vu_syscall_handler(s, lseek) = lseek;

	two->ht1 = vuht_pathadd(CHECKPATH,"/","/unreal","unreal",0,"",s,0,NULL,NULL);
	two->ht2 = vuht_pathadd(CHECKPATH,"/","/unreal","unreal",0,"",s,0,NULL,NULL);
	return two;
}

void vu_unreal_fini(void *private) {
	struct twohte *two = private;
	if (vuht_del(two->ht2) == 0 && vuht_del(two->ht1) == 0) {
		vuht_free(two->ht2);
		vuht_free(two->ht1);
		free(two);
	}
#if 0
	if (two->ht2 && vuht_del(two->ht2) == 0) {
		vuht_free(two->ht2);
		two->ht2 = NULL;
	}
	if (two->ht1 && vuht_del(two->ht1) == 0) {
		vuht_free(two->ht2);
		two->ht1 = NULL;
	}
	if (two->ht1 == NULL && two->ht2 == NULL)
		free(two);
#endif
}
