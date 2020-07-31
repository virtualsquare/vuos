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

#include <vumodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <strcase.h>
#include <stropt.h>
#include <vufs.h>

static int vufs_confirm(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vufs_t *vufs = vuht_get_private_data(ht);
	char *path = arg;
	char *shortpath = path + vuht_get_objlen(ht);
	char **exception;

	for (exception = vufs->except; *exception; exception++) {
		int len = strlen(*exception);
		if (strncmp(shortpath,*exception,len) == 0 &&
				(shortpath[len] == '/' || shortpath[len]=='\0'))
			return 0;
	}
	return 1;
}

static int set_mount_options(const char *input, struct vufs_t *vufs) {
	int tagc = stropt(input, NULL, NULL, 0);
	int retval = 0;
	if(tagc > 1) {
		char buf[strlen(input)+1];
		char *tags[tagc];
		char *args[tagc];
		int excl_choice = 0;
		stropt(input, tags, args, buf);
		for (int i=0; tags[i] != NULL; i++) {
			uint64_t strcasetag = strcase(tags[i]);
			if (vufs == NULL) {
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						retval++;
						if (args[i] == NULL) {
							printk(KERN_ERR "vufs: %s requires an arg\n", tags[i]);
							return -1;
						}
						break;
					case STRCASE(m,o,v,e):
					case STRCASE(m,e,r,g,e):
					case STRCASE(c,o,w):
					case STRCASE(m,i,n,c,o,w):
						if (args[i] != NULL) {
							printk(KERN_ERR "vufs: %s need no args\n", tags[i]);
							return -1;
						}
						if (++excl_choice > 1) {
							printk(KERN_ERR "vufs: move, merge, cow and mincow are mutually exclusive\n", tags[i]);
							return -1;
						}
						break;
					default:
						printk(KERN_ERR "vufs: %s unknown tag\n", tags[i]);
						return -1;
						break;
				}
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						retval++;
						break;
				}
			} else {
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						vufs->except[retval++] = strdup(args[i]);
						vufs->except[retval] = NULL;
						break;
					case STRCASE(m,o,v,e):
						break;
					case STRCASE(m,e,r,g,e):
						vufs->flags |= VUFS_MERGE;
						break;
					case STRCASE(c,o,w):
						vufs->flags |= VUFS_COW;
						break;
					case STRCASE(m,i,n,c,o,w):
						vufs->flags |= VUFS_MINCOW;
						break;
				}
			}
		}
	}
	return retval;
}

int vu_vufs_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	struct vufs_t *new_vufs;
	int nexcept;
	if (data == NULL)
		data = "";
	if ((nexcept = set_mount_options(data, NULL)) < 0) {
		errno = EINVAL;
		return -1;
	}

	new_vufs = malloc(sizeof(struct vufs_t) + sizeof(char *) * (nexcept + 1));
	if (new_vufs == NULL) {
		errno = ENOMEM;
		goto mallocerr;
	}
	new_vufs->source = strdup(source);
	new_vufs->target = strdup(target);
	new_vufs->except[0] = 0;
	new_vufs->rdirfd = -1;
	new_vufs->vdirfd = -1;
	new_vufs->ddirfd = -1;
	new_vufs->flags = 0;
	set_mount_options(data, new_vufs);
	new_vufs->vdirfd = open(source, O_PATH);
	if (new_vufs->vdirfd < 0) {
		errno = ENOENT;
		goto vdirerr;
	}
	if (new_vufs->flags & VUFS_TYPEMASK) {
		new_vufs->rdirfd = open(target, O_PATH);
		if (new_vufs->rdirfd < 0) {
			errno = ENOENT;
			goto rdirerr;
		}
		switch (new_vufs->flags & VUFS_TYPEMASK) {
			case VUFS_COW:
			case VUFS_MINCOW:
				mkdirat(new_vufs->vdirfd, ".-", 0777);
		}
		new_vufs->ddirfd = openat(new_vufs->vdirfd, ".-", O_PATH, 0777);
	}
	pthread_mutex_init(&(new_vufs->mutex), NULL);
	pthread_mutex_lock(&(new_vufs->mutex));

	vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, vufs_confirm, new_vufs);

	pthread_mutex_unlock(&(new_vufs->mutex));
	errno = 0;
	return 0;
rdirerr:
	close(new_vufs->vdirfd);
vdirerr:
	free(new_vufs);
mallocerr:
	return -1;
}

int vu_vufs_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	int ret_value;
	if ((ret_value = vuht_del(ht, flags)) < 0) {
		errno = -ret_value;
		return -1;
	}
	return 0;
}

void vu_vufs_cleanup(uint8_t type, void *arg, int arglen,struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
		struct vufs_t *vufs = vuht_get_private_data(ht);
		if (vufs == NULL) {
			errno = EINVAL;
		} else {
			if (vufs->ddirfd >= 0)
				close(vufs->ddirfd);
			if (vufs->rdirfd >= 0)
				close(vufs->rdirfd);
			close(vufs->vdirfd);
			pthread_mutex_destroy(&(vufs->mutex));
			free(vufs->source);
			free(vufs->target);
			free(vufs);
		}
	}
}

void *vu_vufs_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	/* the following assignments set the actual glibc function
	 * as the handler for every SC this module does not virtualize
	 * this tells the hypervisor to use the original implementation
	 * of the SC instead of the one provided by the module
	 * */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, read) = read;
	vu_syscall_handler(s, write) = write;
	vu_syscall_handler(s, lseek) = lseek;
	vu_syscall_handler(s, pread64) = pread;
	vu_syscall_handler(s, pwrite64) = pwrite;
	vu_syscall_handler(s, fcntl) = fcntl;

#pragma GCC diagnostic pop
	return NULL;
}

int vu_vufs_fini(void *private) {
	return 0;
}

char *vsyscalls[] = { [0] = "vufs_copyfile" };

struct vu_module_t vu_module = {
	.name = "vufs",
	.description = "vu filesystem patchworking",
	.mod_nr_vsyscalls = 1,
	.vsyscalls = vsyscalls
};

__attribute__((constructor))
	static void init(void) {
		debug_set_name(V, "VUFS");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(V, "");
	}
