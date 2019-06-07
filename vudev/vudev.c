/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   with contributions by Alessio Volpe <alessio.volpe3@studio.unibo.it>
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
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/sysmacros.h>
#include <stropt.h>
#include <strcase.h>
#include <vumodule.h>
#include <vudev.h>

VU_PROTOTYPES(vudev)

	struct vu_module_t vu_module = {
		.name = "vudev",
		.description = "vu virtual devices"
	};

#define VUDEVFLAGS_DEVID 1

struct vudev_t {
	void *dlhandle;
	struct vudev_operations_t *devops;

	pthread_mutex_t mutex;
	unsigned int flags;

	struct vu_stat stat;

	int inuse;

	void *private_data;

	struct vuht_entry_t *path_ht;
	struct vuht_entry_t *dev_ht;
};

void *vudev_get_private_data(struct vudev_t *vudev) {
	if (vudev == NULL)
		return NULL;
	else
		return vudev->private_data;
}

void vudev_set_devtype(struct vudev_t *vudev, mode_t devtype) {
	if (S_ISCHR(devtype) || S_ISBLK(devtype))
		vudev->stat.st_mode = (vudev->stat.st_mode & ~S_IFMT) | (devtype & S_IFMT);
}

static int vudev_get_subdev(const char *pathname, struct vuht_entry_t *ht, struct vudev_t *vudev) {
	if (ht == vudev->dev_ht) {
		const dev_t *rdev = vuht_get_obj(ht);
		return minor(*rdev) - minor(vudev->stat.st_rdev);
	} else
		return strtoul(pathname, NULL, 0);
}

int vu_vudev_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct vudevfd_t *vudevfd = malloc(sizeof(struct vudevfd_t));
	struct vuht_entry_t *ht = vu_mod_getht();
	struct vudev_t *vudev = vu_get_ht_private_data();
	int retval;
	if (vudevfd == NULL) {
		errno = ENOMEM;
		return -1;
	}
	vudevfd->subdev = vudev_get_subdev(pathname, ht, vudev);
	vudevfd->offset = 0;
	vudevfd->flags = flags;
	vudevfd->fdprivate = NULL;
	vudevfd->vudev = vudev;
	/* access control */
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->open ? vudev->devops->open(pathname, mode, vudevfd) : (errno = ENOSYS, -1);
	if (retval >= 0)
		*fdprivate = vudevfd;
	else
		free(vudevfd);
	pthread_mutex_unlock(&(vudev->mutex));
	printkdebug(D,"OPEN path:%s flags:%d -> %d %p", pathname, flags, retval, vudevfd);
	return retval;
}

int vu_vudev_close(int fd, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	int retval;
	printkdebug(D,"CLOSE %p", vudevfd);
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->close ? vudev->devops->close(fd, vudevfd) : (errno = ENOSYS, -1);
	if (retval == 0)
		free(vudevfd);
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

ssize_t vu_vudev_read(int fd, void *buf, size_t count, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	ssize_t retval;
	printkdebug(D,"READ %d %p", fd, vudevfd);
	if((vudevfd->flags & O_WRONLY) != 0) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&(vudev->mutex));
	if(vudev->devops->read)
		retval = vudev->devops->read(fd, buf, count, vudevfd);
	else {
		retval = vudev->devops->pread ?
			vudev->devops->pread(fd, buf, count, vudevfd->offset, vudevfd) : (errno = ENOSYS, -1);
		if (retval > 0)
			vudevfd->offset += retval;
	}
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

ssize_t vu_vudev_write(int fd, const void *buf, size_t count, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	ssize_t retval;
	printkdebug(D,"WRITE %d %p", fd, vudevfd);
	if((vudevfd->flags & O_RDONLY) != 0) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&(vudev->mutex));
	if(vudev->devops->write)
		retval = vudev->devops->write(fd, buf, count, vudevfd);
	else {
		retval = vudev->devops->pwrite ?
			vudev->devops->pwrite(fd, buf, count, vudevfd->offset, vudevfd) : (errno = ENOSYS, -1);
		if (retval > 0)
			vudevfd->offset += retval;
	}
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

ssize_t vu_vudev_pread64(int fd, void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	ssize_t retval;
	printkdebug(D,"PREAD %d %p", fd, vudevfd);
	if((vudevfd->flags & O_WRONLY) != 0) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->pread ? vudev->devops->pread(fd, buf, count, offset, vudevfd) : (errno = ENOSYS, -1);
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

ssize_t vu_vudev_pwrite64(int fd, const void *buf, size_t count, off_t offset, int flags, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	ssize_t retval;
	printkdebug(D,"PWRITE %d %p", fd, vudevfd);
	if((vudevfd->flags & O_RDONLY) != 0) {
		errno = EBADF;
		return -1;
	}
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->pwrite ? vudev->devops->pwrite(fd, buf, count, offset, vudevfd) : (errno = ENOSYS, -1);
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

int vu_vudev_access(char *path, int mode, int flags) {
	return 0;
}

off_t vu_vudev_lseek(int fd, off_t offset, int whence, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vudevfd->vudev;
	off_t retval;
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->lseek ? vudev->devops->lseek(fd, offset, whence, vudevfd) : (errno = ENOSYS, -1);
	if (retval != -1)
		vudevfd->offset = retval;
	pthread_mutex_unlock(&(vudev->mutex));
	printkdebug(D,"LSEEK %d %p retval %lu", fd, vudevfd, retval);
	return retval;
}

int vu_vudev_ioctl(int fd, unsigned long request, void *buf, uintptr_t addr, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vu_get_ht_private_data();
	int retval;
	printkdebug(D,"IOCTL %d %p %ld", fd, vudevfd, request);
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->ioctl ? vudev->devops->ioctl(fd, request, buf, vudevfd) : (errno = ENOSYS, -1);
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

int vu_vudev_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate) {
	struct vudevfd_t *vudevfd = fdprivate;
	struct vudev_t *vudev = vu_get_ht_private_data();
	int retval;
	printkdebug(D,"EPOLL_CTL %d %p %d", fd, vudevfd, op);
	pthread_mutex_lock(&(vudev->mutex));
	retval = vudev->devops->epoll_ctl ?
		vudev->devops->epoll_ctl(epfd, op, fd, event, vudevfd) : (errno = ENOSYS, -1);
	pthread_mutex_unlock(&(vudev->mutex));
	return retval;
}

int vu_vudev_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	struct vudev_t *vudev = vu_get_ht_private_data();
	printkdebug(D,"LSTAT %s", pathname);
	memcpy(buf, &vudev->stat, sizeof(struct vu_stat));
	buf->st_rdev = makedev(major(buf->st_rdev), minor(buf->st_rdev) +
			vudev_get_subdev(pathname, ht, vudev));
	return 0;
}

int vu_vudev_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	struct vudev_t *vudev = vu_get_ht_private_data();
	printkdebug(D,"LCHOWN %s", pathname);
	/* XXX access control */
	pthread_mutex_lock(&(vudev->mutex));
	if (owner != (uid_t) -1)
		vudev->stat.st_uid = owner;
	if (group != (gid_t) -1)
		vudev->stat.st_gid = group;
	vudev->stat.st_ctime = time(NULL);
	pthread_mutex_unlock(&(vudev->mutex));
	return 0;
}

int vu_vudev_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	struct vudev_t *vudev = vu_get_ht_private_data();
	printkdebug(D,"LCHMOD %s", pathname);
	/* XXX access control */
	pthread_mutex_lock(&(vudev->mutex));
	vudev->stat.st_mode = (vudev->stat.st_mode & S_IFMT) | (mode & (S_IRWXU|S_IRWXG|S_IRWXO));
	pthread_mutex_unlock(&(vudev->mutex));
	return 0;
}

static int vudev_confirm_path(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vudev_t *vudev = vuht_get_private_data(ht);
	char *path = arg;
	int subdev = strtoul(path + vuht_get_objlen(ht), NULL, 0);
	if (subdev < 0)
		return 0;
	else if (vudev->devops->confirm_subdev)
		return vudev->devops->confirm_subdev(subdev, vudev);
	else
		return subdev == 0;
}

static int vudev_confirm_dev(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vudev_t *vudev = vuht_get_private_data(ht);
	dev_t *dev = arg;
	if (major(*dev) != major(vudev->stat.st_rdev))
		return 0;
	else {
		int subdev = minor(*dev) - minor(vudev->stat.st_rdev);
		if (subdev < 0)
			return 0;
		else if (vudev->devops->confirm_subdev)
			return vudev->devops->confirm_subdev(subdev, vudev);
		else
			return subdev == 0;
	}
}

static void set_mount_options(const char *input, struct vudev_t *vudev) {
	int tagc = stropt(input, NULL, NULL, 0);
	if(tagc > 1) {
		char buf[strlen(input)+1];
		char *tags[tagc];
		char *args[tagc];
		stropt(input, tags, args, buf);
		for (int i=0; tags[i] != NULL; i++) {
			if (args[i]) {
				switch(strcase(tags[i])) {
					case STRCASE(m,o,d,e):
						vudev->stat.st_mode = (vudev->stat.st_mode & S_IFMT) | (strtoul(args[i], NULL, 8) & 0777);
						break;
					case STRCASE(u,i,d):
						vudev->stat.st_uid = strtoul(args[i], NULL, 0);
						break;
					case STRCASE(g,i,d):
						vudev->stat.st_gid = strtoul(args[i], NULL, 0);
						break;
					case STRCASE(m,a,j,o,r):
						vudev->stat.st_rdev = makedev(strtoul(args[i], NULL, 0), minor(vudev->stat.st_rdev));
						break;
					case STRCASE(m,i,n,o,r):
						vudev->stat.st_rdev = makedev(major(vudev->stat.st_rdev), strtoul(args[i], NULL, 0));
						break;
				}
			} else {
				switch(strcase(tags[i])) {
					case STRCASE(c,h,r,d,e,v):
					case STRCASE(c,h,a,r):
					case STRCASE(c,h,r):
						vudev->stat.st_mode &= ~S_IFMT;
						vudev->stat.st_mode |= S_IFCHR;
						break;
					case STRCASE(b,l,k,d,e,v):
					case STRCASE(b,l,k):
						vudev->stat.st_mode &= ~S_IFMT;
						vudev->stat.st_mode |= S_IFBLK;
						break;
					case STRCASE(d,e,v,i,d):
						vudev->flags |= VUDEVFLAGS_DEVID;
						break;
				}
			}
		}
	}
}

int vu_vudev_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {

	struct vudev_operations_t *devops = NULL;
	void *dlhandle = vu_mod_dlopen(filesystemtype, RTLD_NOW);
	if (data == NULL)
		data = "";
	printkdebug(D,"MOUNT source:%s target:%s type:%s flags:0x%x data:%s",
			source, target, filesystemtype, mountflags, data);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	if(dlhandle == NULL ||
			(devops = dlsym(dlhandle,"vudev_ops")) == NULL) {
#pragma GCC diagnostic pop
		if (dlhandle != NULL) {
			printk(KERN_ERR "%s",dlerror());
			dlclose(dlhandle);
		}
		errno = ENOSYS;
		return -1;
	} else {
		struct vu_service_t *s = vu_mod_getservice();
		struct vudev_t *new = malloc(sizeof(struct vudev_t));
		struct vu_stat tstat;

		if (new == NULL)
			goto err_nomem_dev;
		new->dlhandle = dlhandle;
		memset(&new->stat, 0, sizeof(struct vu_stat));
		new->stat.st_blksize = getpagesize();
		new->stat.st_mode = S_IFCHR | 0600;
		new->stat.st_uid = getuid();
		new->stat.st_gid = getgid();
		new->stat.st_atime = new->stat.st_ctime = new->stat.st_mtime = time(NULL);
		if (vu_stat(target, &tstat) == 0) {
			new->stat.st_rdev = tstat.st_rdev;
			if (S_ISCHR(tstat.st_mode) | S_ISBLK (tstat.st_mode))
				new->stat.st_mode = (tstat.st_mode & S_IFMT) | 0600;
		}
		new->flags = 0;
		new->devops = devops;

		new->private_data = NULL;

		set_mount_options(data, new);

		pthread_mutex_init(&(new->mutex), NULL);

		pthread_mutex_lock(&(new->mutex));
		if (devops->init) {
			new->private_data = devops->init(source, mountflags, data, new);
			if (new->private_data == NULL)
				goto err_init_null;
		}
		new->path_ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags,
				data, s, 1, vudev_confirm_path, new);
		if (new->flags & VUDEVFLAGS_DEVID) {
			if(S_ISCHR(new->stat.st_mode))
				new->dev_ht = vuht_add(CHECKCHRDEVICE, NULL, 0, s, vudev_confirm_dev, new, 0);
			else if(S_ISBLK(new->stat.st_mode))
				new->dev_ht = vuht_add(CHECKBLKDEVICE, NULL, 0, s, vudev_confirm_dev, new, 0);
		} else
			new->dev_ht = NULL;
		pthread_mutex_unlock(&(new->mutex));
		return 0;
err_init_null:
		pthread_mutex_unlock(&(new->mutex));
		free(new);
		dlclose(dlhandle);
		errno = EINVAL;
		return -1;
err_nomem_dev:
		dlclose(dlhandle);
		errno = ENOMEM;
		return -1;
	}
}

int vu_vudev_umount2(const char *target, int flags) {
	struct vudev_t *vudev = vu_get_ht_private_data();

	if (vudev == NULL) {
		errno = EINVAL;
		return -1;
	} else  {
		pthread_mutex_lock(&(vudev->mutex));
		if (vudev->inuse && !(flags & MNT_DETACH)) {
			pthread_mutex_unlock(&(vudev->mutex));
			errno = EBUSY;
			return -1;
		} else {
			/*cleanup and umount_internal will do the right umounting sequence in a lazy way*/

			if (vudev->path_ht != NULL)
				vuht_del(vudev->path_ht, flags);
			if (vudev->dev_ht != NULL)
				vuht_del(vudev->dev_ht, flags);

			pthread_mutex_unlock(&(vudev->mutex));
			printkdebug(D,"UMOUNT target:%s flags:%d %p", target, flags, vudev);
			return 0;
		}
	}
}

void vu_vudev_cleanup(uint8_t type, void *arg, int arglen,struct vuht_entry_t *ht) {
	struct vudev_t *vudev = vuht_get_private_data(ht);
	switch (type) {
		case CHECKPATH:
			vudev->path_ht = NULL;
			break;
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
			vudev->dev_ht = NULL;
			break;
	}
	if(vudev->path_ht == NULL && vudev->dev_ht == NULL) {
		printkdebug(D,"CLEANUP %p", vudev);
		if(vudev->devops->fini)
			vudev->devops->fini(vudev->private_data);
		pthread_mutex_destroy(&(vudev->mutex));
		dlclose(vudev->dlhandle);
		free(vudev);
	}
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(D, "VUDEV");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(D, "");
	}
