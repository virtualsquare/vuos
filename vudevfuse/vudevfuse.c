/*
 * vudevfuse: /dev/fuse - virtual fuse kernel support
 * Copyright 2022 Renzo Davoli
 *     Virtualsquare & University of Bologna
 *
 * vudevfuse.c: main file of the module. init/fini mount/umount
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <stropt.h>
#include <strcase.h>
#include <vumodule.h>

#include <vudevfuse.h>
#include <devfuse.h>
#include <eventsem.h>

struct vuht_entry_t *devfuse_ht;

VU_PROTOTYPES(fuse)

	struct vu_module_t vu_module = {
		.name = "fuse",
		.description = "vu fuse device",
		.flags = VUDEVFUSE_MODULE_FLAGS
	};

static int parse_mount_fd(const char *input) {
	int fd = -1;
	int tagc = stropt(input, NULL, NULL, 0);
	if(tagc > 1) {
		char buf[strlen(input)+1];
		char *tags[tagc];
		char *args[tagc];
		stropt(input, tags, args, buf);
		for (int i=0; tags[i] != NULL; i++) {
			if (args[i]) {
				switch(strcase(tags[i])) {
					case STRCASE(f,d):
						fd = strtoul(args[i], NULL, 0);
						break;
				}
			}
		}
	}
	return fd;
}

static void parse_mount_options(struct fusemount_t *fusemount, const char *input) {
	int tagc = stropt(input, NULL, NULL, 0);
	if(tagc > 1) {
		char buf[strlen(input)+1];
		char *tags[tagc];
		char *args[tagc];
		stropt(input, tags, args, buf);
		for (int i=0; tags[i] != NULL; i++) {
			if (args[i]) {
				switch(strcase(tags[i])) {
					case STRCASE(f,d):
						break;
					case STRCASE(r,o,o,t,m,o,d,e):
						fusemount->rootmode = strtoul(args[i], NULL, 8);
						break;
					case STRCASE(u,s,e,r,underscore,i,d):
						fusemount->uid = strtoul(args[i], NULL, 0);
						break;
					case STRCASE(g,r,o,u,p,underscore,i,d):
						fusemount->gid = strtoul(args[i], NULL, 0);
						break;
				}
			} else {
				switch(strcase(tags[i])) {
#if 0
					case STRCASE(c,h,r,d,e,v):
						break;
#endif
				}
			}
		}
	}
}

static int fusemount_confirm(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	(void) type;
	(void) arg;
	(void) arglen;
	struct fusemount_t *fusemount = vuht_get_private_data(ht);
	//printk("fusemount_confirm %p\n", fusemount);
	pthread_mutex_lock(&(fusemount->mutex));
	int retvalue = fusemount->initdata.major > 0;
	pthread_mutex_unlock(&(fusemount->mutex));
	return retvalue;
}

int vu_fuse_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	int fd;
	struct vuht_entry_t *fdht;
	struct fusemount_t *fusemount;

	fd = parse_mount_fd(data);
	if (fd < 0 ||
			((fdht = vu_mod_fd_get_ht(fd)) != devfuse_ht) ||
			(vu_mod_fd_get_sfd(fd, (void **) &fusemount) < 0) ||
			fusemount == NULL)
		return errno = EFAULT, -1;

	if (fusemount->ht != NULL)
		return errno = EBUSY, -1;

	printkdebug(U,"MOUNT source:%s target:%s type:%s flags:0x%x data:%s",
			source, target, filesystemtype, mountflags, data);

	pthread_mutex_lock(&(fusemount->mutex));
	fusemount->mountflags = mountflags;
	parse_mount_options(fusemount, data);
	fusemount->ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags,
			data, s, 0, fusemount_confirm, fusemount);

	pthread_mutex_unlock(&(fusemount->mutex));
	sem_V(fusemount->sem);
	return 0;
}

int vu_fuse_umount2(const char *target, int flags) {
	struct fusemount_t *fusemount = vu_get_ht_private_data();
	if (fusemount == NULL) {
		errno = EINVAL;
		return -1;
	} else  {
		int retval;
		sem_V(fusemount->sem);
		pthread_mutex_lock(&(fusemount->mutex));
		if ((retval = vuht_del(fusemount->ht, flags)) == 0)
			fusemount->ht = NULL;
		pthread_mutex_unlock(&(fusemount->mutex));
		printkdebug(U,"UMOUNT target:%s flags:%d %p = %d", target, flags, fusemount, retval);
		return retval;
	}
}

void vu_fuse_cleanup(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	(void) type;
	(void) arg;
	(void) arglen;
	(void) ht;
	struct fusemount_t *fusemount = vu_get_ht_private_data();
	printkdebug(U,"CLEANUP %p", fusemount);
	if (fusemount != NULL)
		fusemount_free(fusemount);
}

void *vu_fuse_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	printkdebug(U,"INIT");
	devfuse_ht = vuht_pathadd(CHECKPATH,"none","/dev/fuse","devfuse",0,"",s,0,NULL,NULL);
	return NULL;
}

int vu_fuse_fini(void *private) {
	(void) private;
	if (devfuse_ht != NULL) {
		printkdebug(U,"FINI");
		return vuht_del(devfuse_ht, MNT_FORCE);
	}
	return 0;
}

__attribute__((constructor))
	static void fuse_init(void) {
		debug_set_name(U, "+FUSE");
	}

__attribute__((destructor))
	static void fuse_fini(void) {
		debug_set_name(U, "");
	}
