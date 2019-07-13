/*
 *   VUOS: view OS project
 *   Copyright (C) 2019  Renzo Davoli <renzo@cs.unibo.it> VirtualSquare team.
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
 *   vumisc: miscellaneous virtualization.
 *   set single system call behavior, an info file system permits configuration.
 *   e.g.: 
 *      vu_insmod vumisc
 *      vumount -t vumisctime none /tmp/time
 *   pseudo file in /tmp/time change the user processes' perception of time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <vumodule.h>
#include <libvumod.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <vumisc.h>

#define VUMISC_SC \
    VUMISC(clock_settime), \
    VUMISC(clock_getres), \
    VUMISC(clock_gettime)

/* const char *vumisc_names[] = {"clock_gettime", ....}; */
#define VUMISC(X) #X
const char * vumisc_names[] = { VUMISC_SC };
#undef VUMISC

/* const int vumisc_nr[] = {__NR_clock_gettime, ....}; */
#define VUMISC(X) __NR_ ## X
const int vumisc_nr[] = { VUMISC_SC };
#undef VUMISC

/* enum vumisc_index[] = {VUMISC_clock_gettime, ....}; */
#define VUMISC(X) VUMISC_ ## X
enum vumisc_index { VUMISC_SC, NUM_VUMISC_SC };

VU_PROTOTYPES(vumisc)

	struct vu_module_t vu_module = {
		.name = "vumisc",
		.description = "system call virtualization using info file system"
	};

struct vumisc_t {
	void *dlhandle;
	pthread_mutex_t mutex;
	struct vumisc_operations_t *misc_ops;
	void *private_data;
	struct vuht_entry_t *path_ht;
	syscall_t ops[NUM_VUMISC_SC];
	struct vuht_entry_t *ops_ht[NUM_VUMISC_SC];
};

static struct vumisc_info *infofs_getinfo(struct vumisc_info *infotree, const char *pathname) {
	struct vumisc_info *scan;
	for (scan = infotree; scan->path != NULL; scan++) {
		if (strcmp(pathname, scan->path) == 0)
			break;
	}
	return scan;
}

static ino_t ino_hash(const char* path) {
	ino_t hash = 2;
	while (*path)
		hash = 17 * hash ^ (unsigned char) *path++;
	return hash;
}

static int vumisc_dir(int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	char *prefix = pseudoprivate;
	size_t prefixlen = strlen(prefix);
	if (tag == PSEUDOFILE_LOAD_DIRENTS) {
		struct vumisc_info *scan;
		pseudofile_filldir(f, ".", 2, DT_DIR);
		pseudofile_filldir(f, "..", 2, DT_DIR);
		for (scan = vumisc->misc_ops->infotree; scan->path != NULL; scan++) {
			if (strncmp(prefix, scan->path, prefixlen) == 0 &&
					scan->path[prefixlen] == '/' &&
					scan->path[prefixlen + 1] != 0 &&
					strchr(scan->path + (prefixlen + 1), '/') == NULL) {
				ino_t ino = scan->stat.st_ino;
				if (ino == 0)
					ino = ino_hash(scan->path);
				pseudofile_filldir(f, scan->path + (prefixlen + 1),
						ino, pseudofile_mode2type(scan->stat.st_mode));
			}
		}
	}
	return 0;
}

static int simple_check_permission(int flags, mode_t mode) {
	switch (flags & O_ACCMODE) {
		case O_RDONLY : return (mode & S_IRUSR);
		case O_WRONLY : return (mode & S_IWUSR);
		case O_RDWR : return (mode & S_IRUSR) && (mode & S_IWUSR);
	}
	return 0;
}

void *vumisc_get_private_data(void) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	return vumisc->private_data;
}

int vu_vumisc_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	struct vumisc_info *scan = infofs_getinfo(vumisc->misc_ops->infotree, pathname);
	if (scan->path != NULL) {
		if (simple_check_permission(flags, scan->stat.st_mode) == 0) 
			return errno = EACCES, -1;
		switch (scan->stat.st_mode & S_IFMT) {
			case S_IFREG:
				pseudofile_open(vumisc->misc_ops->infocontents, scan->upcall_private, flags, fdprivate);
				break;
			case S_IFDIR: 
				{
					char *dirpath = (char *)pathname;
					if (strcmp(dirpath, "/") == 0) dirpath = "";
					pseudofile_open(vumisc_dir, dirpath, flags, fdprivate);
				}
				break;
			default:
				return errno = -EOPNOTSUPP, -1;
		}
		return 0;
	} else 
		return errno = ENOENT, -1;
}

int vu_vumisc_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	struct vumisc_info *scan = infofs_getinfo(vumisc->misc_ops->infotree, pathname);
	struct vu_stat *statbuf = &scan->stat;
	if (statbuf->st_mode != 0) {
		*buf = *statbuf;
		if (buf->st_ino == 0)
			buf->st_ino = ino_hash(pathname);
		return 0;
	} else
		return errno = ENOENT, -1;
}

int vu_vumisc_access(char *path, int mode, int flags) {
	return 0;
}

ssize_t vu_vumisc_readlink(char *path, char *buf, size_t bufsiz) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	struct vumisc_info *scan = infofs_getinfo(vumisc->misc_ops->infotree, path);
	if (S_ISLNK(scan->stat.st_mode))
		return pseudofile_readlink_fill(scan->upcall_private, buf, bufsiz);
	else
		return errno = EINVAL, -1;
}

int vu_vumisc_unlink(const char *pathname) {
	return 0;
}

int vu_vumisc_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	return vumisc->ops[VUMISC(clock_gettime)](clk_id, tp);
}

int vu_vumisc_clock_settime(clockid_t clk_id, const struct timespec *tp) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	return vumisc->ops[VUMISC(clock_settime)](clk_id, tp);
}

int vu_vumisc_clock_getres(clockid_t clk_id, struct timespec *res) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	return vumisc->ops[VUMISC(clock_getres)](clk_id, res);
}

static syscall_t vumisc_getsym(void *handle, const char *filesystemtype, const char *symbol) {
	size_t fullnamelen = strlen(filesystemtype) + strlen(symbol) + 2;
	char fullname[fullnamelen];
	snprintf(fullname, fullnamelen, "%s_%s", filesystemtype, symbol);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	return dlsym(handle, fullname);
#pragma GCC diagnostic pop
}

#if 0
static int vumisc_confirm(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	int *sc = arg;
	printk("%p %d\n", ht, *sc);
	return 1;
}
#endif

int vu_vumisc_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	void *dlhandle = vu_mod_dlopen(filesystemtype, RTLD_NOW);
	struct vumisc_operations_t *misc_ops;
	if (data == NULL)
		data = "";
	printkdebug(M,"MOUNT source:%s target:%s type:%s flags:0x%x data:%s",
			source, target, filesystemtype, mountflags, data);
	if(dlhandle == NULL ||
			(misc_ops = dlsym(dlhandle,"vumisc_ops")) == NULL) {
		if (dlhandle != NULL) {
			printk(KERN_ERR "%s",dlerror());
			dlclose(dlhandle);
		}
		errno = ENOSYS;
		return -1;
	} else {
		struct vu_service_t *s = vu_mod_getservice();
		struct vumisc_t *new = malloc(sizeof(struct vumisc_t));
		int i;
		if (new == NULL)
			goto err_nomem_misc;
		new->dlhandle = dlhandle;
		new->misc_ops = misc_ops;
		for (i = 0; i < NUM_VUMISC_SC; i++)
			new->ops[i] = vumisc_getsym(dlhandle, filesystemtype, vumisc_names[i]);
		pthread_mutex_init(&(new->mutex), NULL);
		pthread_mutex_lock(&(new->mutex));
		if (misc_ops->init) {
      new->private_data = misc_ops->init(source);
			if (new->private_data == NULL)
        goto err_init_null;
    }
		new->path_ht = vuht_pathadd(CHECKPATH, 
				source, target, filesystemtype, mountflags, data, s, 0, NULL, new);
		for (i = 0; i < NUM_VUMISC_SC; i++) {
			if (new->ops[i] != NULL) {
				int vu_syscall = vu_arch_table[vumisc_nr[i]];
				new->ops_ht[i] = vuht_add(CHECKSC, &vu_syscall, sizeof(int), s, NULL, new, 0);
			} else 
				new->ops_ht[i] = NULL;
		}
		pthread_mutex_unlock(&(new->mutex));
		return errno = 0, 0;
err_init_null:
		pthread_mutex_unlock(&(new->mutex));
		free(new);
		dlclose(dlhandle);
		return errno = EINVAL, -1;
err_nomem_misc:
		dlclose(dlhandle);
		return errno = ENOMEM, -1;
	}
}

int vu_vumisc_umount2(const char *target, int flags) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	int i;
	pthread_mutex_lock(&(vumisc->mutex));
	if (vumisc->path_ht != NULL)
		vuht_del(vumisc->path_ht, flags);
	for (i = 0; i < NUM_VUMISC_SC; i++)
		vuht_del(vumisc->ops_ht[i], flags);
	pthread_mutex_unlock(&(vumisc->mutex));
	printkdebug(M,"UMOUNT target:%s flags:%d %p", target, flags, vumisc);
	return 0;
}

void vu_vumisc_cleanup(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	struct vumisc_t *vumisc = vu_get_ht_private_data();
	int i;
	switch (type) {
		case CHECKPATH:
			vumisc->path_ht = NULL;
			break;
		case CHECKSC:
			for(i = 0; i < NUM_VUMISC_SC; i++) {
				int vu_syscall = * (int *)(arg);
				if (vu_syscall == vumisc_nr[i]) {
					vumisc->ops_ht[i] = NULL;
					break;
				}
			}
	}
	if (vumisc->path_ht == NULL) {
		for(i = 0; i < NUM_VUMISC_SC; i++) {
			if (vumisc->ops_ht[i] != NULL)
				break;
		}
		if (i == NUM_VUMISC_SC) {
			printkdebug(M,"CLEANUP %p", vumisc);
			if(vumisc->misc_ops->fini)
				vumisc->misc_ops->fini(vumisc->private_data);
			pthread_mutex_destroy(&(vumisc->mutex));
			dlclose(vumisc->dlhandle);
			free(vumisc);
		}
	}
}

void *vu_vumisc_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, close) = pseudofile_close;
	vu_syscall_handler(s, read) = pseudofile_read;
	vu_syscall_handler(s, write) = pseudofile_write;
	vu_syscall_handler(s, lseek) = pseudofile_lseek;
	vu_syscall_handler(s, getdents64) = pseudofile_getdents64;
#pragma GCC diagnostic pop
	return NULL;
}

int vu_vumisc_fini(void *private) {
	return 0;
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(M, "VUMISC");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(M, "");
	}

