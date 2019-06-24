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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include <asm/ioctl.h>

#include <linux/hdreg.h>

#include <vudev.h>
#include <stropt.h>
#include <strcase.h>
#include <vumodule.h>

#define STD_SIZE (64*1024)
#define STD_SECTORSIZE 512

#define READONLY 1
#define MBR 2

#define RAMDISK_SIZE(ramdisk) (ramdisk->rd_size * STD_SECTORSIZE)
#define GET_CYLINDERS(ramdisk) \
  ((ramdisk->rd_size + (ramdisk->geometry.heads*ramdisk->geometry.sectors) -1) / (ramdisk->geometry.heads*ramdisk->geometry.sectors))

struct vuramdisk_t {
  char flags;
	char *diskdata;
	size_t rd_size;
	struct hd_geometry geometry;
};

/******************************************************************************/
/************************************UTILS*************************************/

static inline ssize_t _get_size(char unit, ssize_t size) {
  switch (unit) {
    case 'k':
		case 'K': size *= 1024 / STD_SECTORSIZE; return size;
		case 'm':
		case 'M': size *= 1024 * 1024 / STD_SECTORSIZE; return size;
		case 'g':
		case 'G': size *= 1024 * 1024 * 1024 / STD_SECTORSIZE; return size;
    default: return size;
  }
}

static inline ssize_t _get_strsize(char *size) {
	return _get_size(size[strlen(size) - 1], strtoull(size, NULL, 0));
}

static void set_mount_options(const char *input, struct vuramdisk_t *ramdisk) {
	int tagc = stropt(input, NULL, NULL, 0);
	if(tagc > 1) {
    char buf[strlen(input)+1];
    char *tags[tagc];
    char *args[tagc];
    stropt(input, tags, args, buf);
		for (int i=0; tags[i] != NULL; i++) {
			switch(strcase(tags[i])) {
				case STRCASE(s,i,z,e):
					if (args[i])
						ramdisk->rd_size = _get_strsize(args[i]);
					break;
				case STRCASE(m,b,r):
					ramdisk->flags = MBR;
					break;
			}
    }
  }
}

static inline ssize_t _ck_size(struct vuramdisk_t *ramdisk, size_t count, off_t offset) {
  if((size_t) offset >= RAMDISK_SIZE(ramdisk))
    return 0;
  count = (offset + count <= RAMDISK_SIZE(ramdisk))? count: (RAMDISK_SIZE(ramdisk) - offset);
  return count;
}

/******************************************************************************/
/***********************************SYSCALL************************************/

int vuramdisk_open(const char *pathname, mode_t mode,  struct vudevfd_t *vudevfd) {
  return 0;
}

int vuramdisk_close(int fd, struct vudevfd_t *vudevfd) {
  return 0;
}

ssize_t vuramdisk_pread(int fd, void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd) {
	struct vuramdisk_t *ramdisk = vudev_get_private_data(vudevfd->vudev);
	count = _ck_size(ramdisk, count, offset);
  memcpy(buf, (ramdisk->diskdata + offset), count);
	return count;
}

ssize_t vuramdisk_pwrite(int fd, const void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd) {
	struct vuramdisk_t *ramdisk = vudev_get_private_data(vudevfd->vudev);
  if(ramdisk->flags & READONLY) {
    errno = EBADF;
		return -1;
  }
	count = _ck_size(ramdisk, count, offset);
  memcpy((ramdisk->diskdata + offset), buf, count);
  return count;
}

off_t vuramdisk_lseek(int fd, off_t offset, int whence, struct vudevfd_t *vudevfd) {
	struct vuramdisk_t *ramdisk = vudev_get_private_data(vudevfd->vudev);
  off_t ret_value;
	switch (whence) {
		case SEEK_SET: ret_value = offset; break;
		case SEEK_CUR: ret_value = vudevfd->offset + offset; break;
		case SEEK_END: ret_value = RAMDISK_SIZE(ramdisk) + offset; break;
    default: errno = EINVAL;
						 ret_value = (off_t) -1;
						 break;
	}
	return ret_value;
}

int vuramdisk_ioctl(int fd, unsigned long request, void *addr, struct vudevfd_t *vudevfd){
	if (fd >= 0) {
		struct vuramdisk_t *ramdisk = vudev_get_private_data(vudevfd->vudev);
		switch (request) {
			case BLKROGET:
				*(int *)addr = (ramdisk->flags & READONLY);
				break;
			case BLKROSET:
				ramdisk->flags |= (*(int *)addr > 0)? READONLY:0;
				break;
			case BLKSSZGET:
				*(int *)addr = STD_SECTORSIZE;
				break;
			case BLKGETSIZE:
				*(int *)addr = ramdisk->rd_size * ((ramdisk->flags & MBR)? 1:STD_SECTORSIZE);
				break;
			case BLKGETSIZE64:
				*(long long *)addr = ramdisk->rd_size * STD_SECTORSIZE;
				break;
			case BLKRRPART: break;
			case HDIO_GETGEO:
											memcpy(addr, &(ramdisk->geometry), sizeof(struct hd_geometry));
											break;
			default: errno = EINVAL;
							 return -1;
		}
		return 0;
	} else {
		return -1;
	}
}

void *vuramdisk_init(const char *source, unsigned long flags, const char *args, struct vudev_t *vudev) {
	struct vuramdisk_t *ramdisk;
	if((ramdisk = calloc(1, sizeof(struct vuramdisk_t))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	set_mount_options(args, ramdisk);
	if(ramdisk->rd_size == 0)
		ramdisk->rd_size = STD_SIZE;
	ramdisk->geometry.start = 0;
	if (ramdisk->rd_size == (unsigned int) ramdisk->rd_size) { /* 32 */
		ramdisk->geometry.heads = 16;
		ramdisk->geometry.sectors = 16;
  } else { /* 64 */
		ramdisk->geometry.heads = 128;
		ramdisk->geometry.sectors = 128;
	}
	ramdisk->geometry.cylinders = GET_CYLINDERS(ramdisk);
	ramdisk->rd_size = ramdisk->geometry.heads * ramdisk->geometry.sectors * ramdisk->geometry.cylinders;
	if((ramdisk->diskdata = calloc(1, ramdisk->rd_size * STD_SECTORSIZE)) == NULL) {
		free(ramdisk);
		errno = ENOMEM;
		return NULL;
  }
	vudev_set_devtype(vudev, S_IFBLK);
	return ramdisk;
}

int vuramdisk_fini(void *private_data) {
  struct vuramdisk_t *ramdisk = private_data;
	if (ramdisk) {
		free(ramdisk->diskdata);
		free(ramdisk);
    private_data = NULL;
	}
	return 0;
}

struct vudev_operations_t vudev_ops = {
  .open = vuramdisk_open,
  .close = vuramdisk_close,
	.pread = vuramdisk_pread,
	.pwrite = vuramdisk_pwrite,
  .lseek = vuramdisk_lseek,
  .ioctl = vuramdisk_ioctl,
  .init = vuramdisk_init,
  .fini = vuramdisk_fini,
};
