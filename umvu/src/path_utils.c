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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <canonicalize.h>
#include <epoch.h>
#include <arch_table.h>
#include <service.h>
#include <hashtable.h>
#include <syscall_defs.h>
#include <sys/mount.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <r_table.h>
#include <vu_fs.h>
#include <vu_fd_table.h>
#include <linux_32_64.h>
#include <vu_pushpop.h>
#include <vu_log.h>
#include <path_utils.h>

#define DEFAULT_REALPATH_FLAGS (PERMIT_NONEXISTENT_LEAF | IGNORE_TRAILING_SLASH)

struct realpath_arg_t {
	int dirfd;
	uint8_t nested;
	uint8_t need_rewrite;
	struct vu_stat *statbuf;
};

static inline int realpath_flags(int flags) {
	int retvalue = DEFAULT_REALPATH_FLAGS;
	if (flags & FOLLOWLINK)
		retvalue |= FOLLOWLINK;
	return retvalue;
}

char *get_path(int dirfd, syscall_arg_t addr, struct vu_stat *buf, int flags, uint8_t *need_rewrite) {
	char path[PATH_MAX];
	struct realpath_arg_t realpath_arg = {
		.dirfd = dirfd,
		.nested = 0,
		.need_rewrite = 0,
		.statbuf = buf};
	char *ret_value;
	umvu_peek_str(addr, path, PATH_MAX);
	ret_value = canon_realpath_dup(path, realpath_flags(flags), &realpath_arg);
	printkdebug(p,"get_path %d %s->%s errno:%d epoch:%d rewr:%d", dirfd, path, ret_value, errno, get_vepoch(), realpath_arg.need_rewrite);
	if (need_rewrite)
		*need_rewrite = realpath_arg.need_rewrite;
	return ret_value;
}

int path_check_exceptions(int syscall_number, syscall_arg_t *args) {
	int nargs = vu_arch_table_nargs(syscall_number);
	switch (syscall_number) {
		case __NR_openat:
			return (args[2] & O_NOFOLLOW) ? 3 : 2;
		case __NR_open:
			return (args[1] & O_NOFOLLOW) ? 1 : 0;
		case __NR_umount2:
			return (args[1] & UMOUNT_NOFOLLOW) ? 1 : 0;
		case __NR_unlinkat:
			return 3;
		default:
			return (args[nargs-1] & AT_SYMLINK_NOFOLLOW) ? 3 : 2;
	}
}

char *get_syspath(struct syscall_descriptor_t *sd, struct vu_stat *buf, uint8_t *need_rewrite) {
	int syscall_number = sd->syscall_number;
	int patharg = vu_arch_table_patharg(syscall_number);
	int dirfd = AT_FDCWD;

	if (patharg < 0) {
		errno = 0;
		return NULL;
	} else {
		int flags = FOLLOWLINK;
		int type = vu_arch_table_type(syscall_number);
		if (type == 3)
			type = path_check_exceptions(syscall_number, sd->syscall_args);
		if (type & ARCH_TYPE_SYMLINK_NOFOLLOW)
			flags &= ~FOLLOWLINK;
		if (type & ARCH_TYPE_IS_AT) {
			dirfd = sd->syscall_args[patharg];
			patharg++;
		}
		return get_path(dirfd, sd->syscall_args[patharg], buf, flags, need_rewrite);
	}
}

void rewrite_syspath(struct syscall_descriptor_t *sd, char *newpath) {
  int syscall_number = sd->syscall_number;
  int patharg = vu_arch_table_patharg(syscall_number);

  if (patharg >= 0) {
    int type = vu_arch_table_type(syscall_number);
		if (type == 3)
			type = path_check_exceptions(syscall_number, sd->syscall_args);
    if (type & ARCH_TYPE_IS_AT)
      patharg++;
    sd->syscall_args[patharg] = vu_push(sd, newpath, strlen(newpath) + 1);
  }
}

char *get_vsyspath(struct syscall_descriptor_t *sd, struct vu_stat *buf, uint8_t *need_rewrite) {
	int syscall_number = -sd->syscall_number;
	int patharg = vvu_arch_table_patharg(syscall_number);
	int dirfd = AT_FDCWD;
	if (patharg < 0) {
		errno = 0;
		return NULL;
	} else {
		int flags = FOLLOWLINK;
		int type = vvu_arch_table_type(syscall_number);
		if (type & ARCH_TYPE_SYMLINK_NOFOLLOW)
			flags &= ~FOLLOWLINK;
		return get_path(dirfd, sd->syscall_args[patharg], buf, flags, need_rewrite);
	}
}

char *get_nested_path(int dirfd, char *path, struct vu_stat *buf, int flags, uint8_t *need_rewrite) {
	struct realpath_arg_t realpath_arg = {
		.dirfd = dirfd,
		.nested = 1,
		.need_rewrite = 0,
		.statbuf = buf};
	char *ret_value;
	ret_value = canon_realpath_dup(path, realpath_flags(flags), &realpath_arg);
	printkdebug(p,"get_nested_path %d %s->%s errno:%d epoch:%d rewr:%d", dirfd, path, ret_value, errno, get_vepoch(), realpath_arg.need_rewrite);
	if (need_rewrite)
		*need_rewrite = realpath_arg.need_rewrite;
	return ret_value;
}

char *get_nested_syspath(int syscall_number, syscall_arg_t *args, struct vu_stat *buf, uint8_t *need_rewrite) {
	int patharg = vu_arch_table_patharg(syscall_number);
	int dirfd = AT_FDCWD;
	if (patharg < 0) {
		errno = 0;
		return NULL;
	} else {
		int flags = FOLLOWLINK;
		int type = vu_arch_table_type(syscall_number);
		if (type == 3)
			type = path_check_exceptions(syscall_number, args);
		if (type & ARCH_TYPE_SYMLINK_NOFOLLOW)
			flags &= ~FOLLOWLINK;
		if (type & ARCH_TYPE_IS_AT) {
			dirfd = args[patharg];
			patharg++;
		}
		return get_nested_path(dirfd, (char *)args[patharg], buf, flags, need_rewrite);
	}
}

/* canonicalize's helper functions */
static int vu_access(char *pathname, int mode, void *private) {
	struct vuht_entry_t *ht;
	epoch_t e = get_vepoch();
	int retval;

	ht = vuht_pick(CHECKPATH, pathname, NULL, SET_EPOCH);
	if (ht) {
		retval = service_syscall(ht,__VU_access)(vuht_path2mpath(ht, pathname), mode, 0);
		vuht_drop(ht);
	} else
		retval = r_access(pathname, mode);
	set_vepoch(e);
	return retval;
}

static inline mode_t get_lmode(struct vuht_entry_t *ht, 
		char *pathname, struct vu_stat *buf) {
	int stat_retval;
	if (ht) {
		stat_retval = service_syscall(ht,__VU_lstat)(vuht_path2mpath(ht, pathname), buf, 0, -1, NULL);
	} else
		stat_retval = r_vu_lstat(pathname, buf);
	if (stat_retval == 0)
		return buf->st_mode;
  else
    return buf->st_mode = 0;
}
	
static mode_t vu_lmode(char *pathname, void *private) {
	struct vuht_entry_t *ht;
	struct realpath_arg_t *arg = private;
	epoch_t e = get_vepoch();
	mode_t retval;

	ht = vuht_pick(CHECKPATH, pathname, NULL, SET_EPOCH);

	if (arg->statbuf != NULL) 
		retval = get_lmode(ht, pathname, arg->statbuf);
	else {
		struct vu_stat buf;
		retval = get_lmode(ht, pathname, &buf);
	}
	if (ht) {
		arg->need_rewrite = 1;
		vuht_drop(ht);
	}
	set_vepoch(e);
	return retval;
}

static ssize_t vu_readlink(char *pathname, char *buf, size_t bufsiz, void *private) {
	struct vuht_entry_t *ht;
	epoch_t e = get_vepoch();
	ssize_t retval;

	ht = vuht_pick(CHECKPATH, pathname, NULL, SET_EPOCH);
	if (ht) {
		retval = service_syscall(ht, __VU_readlink)(vuht_path2mpath(ht, pathname), buf, bufsiz);
		vuht_drop(ht);
	} else
		retval = r_readlink(pathname, buf, bufsiz);
	set_vepoch(e);
	return retval;
}

static int vu_getcwd(char *pathname, size_t size, void *private) {
	struct realpath_arg_t *arg = private;
	if (arg->dirfd == AT_FDCWD) {
		if (arg->nested == 0) {
			vu_fs_get_cwd(pathname, size);
			return 0;
		} else 
			return getcwd(pathname, size) == 0 ? -1 : 0;
	} else {
		vu_fd_get_path(arg->dirfd, arg->nested, pathname, size);
		if (*pathname == 0)
			strcpy(pathname, "/");
		return 0;
	}
}

static int vu_getroot(char *pathname, size_t size, void *private) {
	struct realpath_arg_t *arg = private;
	if (arg->nested) {
		pathname[0] = '/';
		pathname[1] = '\0';
	} else
		vu_fs_get_rootdir(pathname, size);
	return 0;
}

__attribute__((constructor))
	static void init(void) {
		struct canon_ops ops = {
			.access = vu_access,
			.lmode = vu_lmode,
			.readlink = vu_readlink,
			.getcwd = vu_getcwd,
			.getroot = vu_getroot,
		};
		canon_setops(&ops);
		debug_set_name(p, "PATH");
	}
