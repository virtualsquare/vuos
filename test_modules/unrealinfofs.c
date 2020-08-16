/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it> VirtualSquare team.
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
 *   Tutorial module for pseudofiles and info file systems.
 *   $ load the module
 *   # mount -t unrealinfofs none /mnt
 *   $ ls -l /mnt
 *   total 0
 *   -r--r--r-- 0 root root 0 Jan  1  1970 date
 *   drwxrwxrwx 0 root root 0 Jan  1  1970 dir
 *   $ ls -l /mnt/dir
 *    total 0
 *   -rw-rw-rw- 0 root root 0 Jan  1  1970 printk
 *   lrwxrwxrwx 0 root root 0 Jan  1  1970 symlink -> /etc/hostname
 *   --w--w--w- 0 root root 0 Jan  1  1970 wronly
 *   $ cat /mnt/date
 *   --- prints the current date and time
 *   $ cat /mnt/dir/symlink
 *   --- prints yout hostname: symlink is a link to /etc/hostname
 *   $ cat /mnt/dir/printk
 *   This file can be read or written
 *   at the end printk shows the contents
 *   $ echo ciao > /mnt/dir/printk
 *   --- ciao appears un umvu's console
 *   $ echo 42 > /mnt/dir/wronly
 *   --- on console "wronly output = 42"
 *   $ echo ciao >  /mnt/dir/wronly
 *   --- on console "wronly accept numbers only"
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <vumodule.h>
#include <libvumod.h>
#include <errno.h>
#include <string.h>
#include <time.h>

VU_PROTOTYPES(unrealinfofs)

	struct vu_module_t vu_module = {
		.name = "unrealinfofs",
		.description = "example of informational file system"
	};

struct info {
	char *path;
	struct vu_stat stat;
	pseudo_upcall upcall;
	void *upcall_private;
};

int upcall_date(int tag, FILE *f, int openflags, void *pseudoprivate);
int upcall_printk(int tag, FILE *f, int openflags, void *pseudoprivate);
int upcall_wronly(int tag, FILE *f, int openflags, void *pseudoprivate);
int upcall_dir(int tag, FILE *f, int openflags, void *pseudoprivate);

struct info infotree[] = {
	{"/", {.st_mode = S_IFDIR | 0777, .st_ino = 2}, upcall_dir, ""},
	{"/date", {.st_mode = S_IFREG | 0444, .st_ino = 5}, upcall_date, NULL},
	{"/dir", {.st_mode = S_IFDIR | 0777, .st_ino = 3}, upcall_dir, "/dir"},
	{"/dir/symlink", {.st_mode = S_IFLNK | 0777, .st_ino = 6}, NULL, "/etc/hostname"},
	{"/dir/printk", {.st_mode = S_IFREG | 0666, .st_ino = 7}, upcall_printk, NULL},
	{"/dir/wronly", {.st_mode = S_IFREG | 0222, .st_ino = 8}, upcall_wronly, NULL},
	{NULL, {.st_mode = 0}, NULL, NULL}
};

static struct info *infofs_getinfo(const char *pathname) {
	struct info *scan;
	for (scan = infotree; scan->path != NULL; scan++) {
		if (strcmp(pathname, scan->path) == 0)
			break;
	}
	return scan;
}

int upcall_date(int tag, FILE *f, int openflags, void *pseudoprivate) {
	if (tag == PSEUDOFILE_LOAD_CONTENTS) {
		time_t now = time(NULL);
		fprintf(f,"%s",ctime(&now));
	}
	return 0;
}

int upcall_printk(int tag, FILE *f, int openflags, void *pseudoprivate) {
	if (tag == PSEUDOFILE_LOAD_CONTENTS &&
			(openflags & O_ACCMODE) == O_RDONLY) {
		fprintf(f, "This file can be read or written\nat the end printk shows the contents\n");
	}
	if (tag == PSEUDOFILE_STORE_CLOSE &&
			(openflags & O_ACCMODE) != O_RDONLY) {
		if (f != NULL) {
			char *line = NULL;
			size_t n = 0;
			while (getline(&line, &n, f) > 0)
				printk("%s",line);
			free(line);
		}
	}
	return 0;
}

int upcall_wronly(int tag, FILE *f, int openflags, void *pseudoprivate) {
	if (tag == PSEUDOFILE_STORE_CLOSE && f != NULL) {
		int n;
		if (fscanf(f, "%d", &n) == 0)
			printk("wronly accept numbers only\n");
		else
			printk("wronly output = %d\n", n);
	}
	return 0;
}

int upcall_dir(int tag, FILE *f, int openflags, void *pseudoprivate) {
	char *prefix = pseudoprivate;
	size_t prefixlen = strlen(prefix);
	if (tag == PSEUDOFILE_LOAD_DIRENTS) {
		struct info *scan;
		pseudofile_filldir(f, ".", 2, DT_DIR);
		pseudofile_filldir(f, "..", 2, DT_DIR);
		for (scan = infotree; scan->path != NULL; scan++) {
			if (strncmp(prefix, scan->path, prefixlen) == 0 &&
					scan->path[prefixlen] == '/' &&
					scan->path[prefixlen + 1] != 0 &&
					strchr(scan->path + (prefixlen + 1), '/') == NULL)
				pseudofile_filldir(f, scan->path + (prefixlen + 1),
						scan->stat.st_ino, pseudofile_mode2type(scan->stat.st_mode));
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

int vu_unrealinfofs_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct info *scan = infofs_getinfo(pathname);
	if (scan->path != NULL) {
		if (simple_check_permission(flags, scan->stat.st_mode) == 0) {
			errno = EACCES;
			return -1;
		}
		if (scan->upcall != NULL)
			pseudofile_open(scan->upcall, scan->upcall_private, flags, fdprivate);
		return 0;
	} else {
		errno = ENOENT;
		return -1;
	}
}

int vu_unrealinfofs_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	struct vu_stat *statbuf = &infofs_getinfo(pathname)->stat;
	if (statbuf->st_mode != 0) {
		*buf = *statbuf;
		return 0;
	} else {
		errno = ENOENT;
		return -1;
	}
}

#if 0
int vu_unrealinfofs_access(char *path, int mode, int flags) {
	return 0;
}
#endif

ssize_t vu_unrealinfofs_readlink(char *path, char *buf, size_t bufsiz) {
	return pseudofile_readlink_fill(infofs_getinfo(path)->upcall_private, buf, bufsiz);
}

int vu_unrealinfofs_unlink(const char *pathname) {
	return 0;
}

int vu_unrealinfofs_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, NULL /*entry*/);
	errno = 0;
	return 0;
}

int vu_unrealinfofs_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	int ret_value;
	if ((ret_value = vuht_del(ht, flags)) < 0) {
		errno = -ret_value;
		return -1;
	}
	return 0;
}

void vu_unrealinfofs_cleanup(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
	}
}

void *vu_unrealinfofs_init(void) {
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

int vu_unrealinfofs_fini(void *private) {
	return 0;
}
