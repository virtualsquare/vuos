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
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <asm/ioctl.h>

#include <linux/hdreg.h>

#include <strcase.h>

#include <vudev.h>
#include <strcase.h>
#include <vumodule.h>

#define STD_SECTORSIZE 							512
#define STD_SECTORSIZE_OFFSET_MASK	0x1ff
#define IS_ALIGNED(offset, count)	\
	((offset&STD_SECTORSIZE_OFFSET_MASK) == 0 && (count&STD_SECTORSIZE_OFFSET_MASK) == 0)

#define RT_BIT(bit)                 (1UL << (bit))
#define VD_OPEN_FLAGS_NORMAL        0
#define VD_OPEN_FLAGS_READONLY      RT_BIT(0)

static void *vboxdd_hdl;
static int vboxdd_count;

static int (*vboxdd_create) ();
static int (*vboxdd_open) ();
static int (*vboxdd_close) ();
static int (*vboxdd_read) ();
static int (*vboxdd_write) ();
static int (*vboxdd_flush) ();
static uint64_t (*vboxdd_get_size) ();
static int (*vboxdd_set_open_flags) ();
static int (*vboxdd_get_LCHS_geometry) ();

struct vuvdi_t {
	int fd;
	void *disk;
  size_t size;
  unsigned long flags;
};

struct vuvdi_pdmmediageom_t {
	uint32_t cHeads;
	uint32_t cSectors;
  uint32_t cCylinders;
};

/******************************************************************************/
/************************************UTILS*************************************/

static int vboxdd_detect_type(int fd, char **disktype) {
	char buf[8];
	read(fd, buf, sizeof(buf));
	if (strncmp (buf, "conectix", 8) == 0)	*disktype = "VHD";
	else if (strncmp (buf, "VMDK", 4) == 0)	*disktype = "VMDK";
	else if (strncmp (buf, "KDMV", 4) == 0) *disktype = "VMDK";
	else if (strncmp (buf, "<<<",  3) == 0) *disktype = "VDI";
	else {
		printk(KERN_ERR "cannot autodetect disk type\n");
		errno = ENODEV;
		return -1;
	}
	printkdebug(D, "disktype [%s]", *disktype);
	return 0;
}

static int dlload_vboxdd(void) {
	if(vboxdd_count)
		return ++vboxdd_count;
	if((vboxdd_hdl = vu_mod_dlopen("/usr/lib/virtualbox/VBoxDD.so", RTLD_NOW)) == NULL) {
		printk(KERN_ERR "VBoxDD library: not found");
		return -1;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vboxdd_create = (int *) dlsym(vboxdd_hdl, "VDCreate");
	vboxdd_open = (int *) dlsym(vboxdd_hdl, "VDOpen");
	vboxdd_close = (int *) dlsym(vboxdd_hdl, "VDClose");
	vboxdd_read = (int *) dlsym(vboxdd_hdl, "VDRead");
	vboxdd_write = (int *) dlsym(vboxdd_hdl, "VDWrite");
	vboxdd_flush = (int *) dlsym(vboxdd_hdl, "VDFlush");
	vboxdd_get_size = (uint64_t *) dlsym(vboxdd_hdl, "VDGetSize");
	vboxdd_set_open_flags = (int *) dlsym(vboxdd_hdl, "VDSetOpenFlags");
	vboxdd_get_LCHS_geometry = (int *) dlsym(vboxdd_hdl, "VDGetLCHSGeometry");
#pragma GCC diagnostic pop
	printkdebug(D, "%p %p %p %p %p %p %p %p",
		vboxdd_create, vboxdd_open, vboxdd_close, vboxdd_read,
		vboxdd_write, vboxdd_flush, vboxdd_get_size, vboxdd_get_LCHS_geometry);
	return ++vboxdd_count;
}

static void dlunload_vboxdd(void) {
	vboxdd_count--;
	if (vboxdd_count == 0) {
		dlclose(vboxdd_hdl);
		vboxdd_hdl=NULL;
	}
}

static inline ssize_t _vuvdi_alined_pread64(void *disk, void *buf, size_t count, off_t offset) {
	if(count == 0) return 0;
	if (IS_ALIGNED(offset, count)) {
		if(vboxdd_read(disk, offset, buf, count) < 0)
			goto read_err_exit;
		return count;
	}
	char tmp_buf[STD_SECTORSIZE];
	size_t over_off, tmp_count, until_count = count;
	/* Read to align the offset to the next block. */
	if((over_off = (offset & STD_SECTORSIZE_OFFSET_MASK))) {
		if(vboxdd_read(disk, (offset - over_off), tmp_buf, STD_SECTORSIZE) < 0)
			goto read_err_exit;
		tmp_count = STD_SECTORSIZE - over_off;
		if(count < tmp_count) tmp_count = count;
		memcpy(buf, (tmp_buf + over_off), tmp_count);
		buf = ((char *) buf) + tmp_count;
		offset += tmp_count;
		until_count -= tmp_count;
	}
	/* Read all blocks contained in count. */
	if((tmp_count = (until_count & ~STD_SECTORSIZE_OFFSET_MASK))) {
		if(vboxdd_read(disk, offset, buf, tmp_count) < 0)
			goto read_err_exit;
		buf = ((char *) buf) + tmp_count;
		offset += tmp_count;
		until_count -= tmp_count;
	}
	if(until_count > 0) { /* until_count < blocksize */
		if(vboxdd_read(disk, offset, tmp_buf, STD_SECTORSIZE) < 0)
			goto read_err_exit;
		memcpy(buf, tmp_buf, until_count);
	}
	return count;
read_err_exit:
	errno = EIO; return -1;
}

static inline ssize_t _vuvdi_alined_pwrite64(void *disk, const void *buf, size_t count, off_t offset) {
	if(count == 0) return 0;
	if(IS_ALIGNED(offset, count)) {
		if(vboxdd_write(disk, offset, buf, count) < 0)
			goto write_err_exit;
		return count;
	}
	char tmp_buf[STD_SECTORSIZE];
	size_t over_off, tmp_count, until_count = count;
	/* Write to align the offset to the next block. */
	if((over_off = (offset & STD_SECTORSIZE_OFFSET_MASK))) {
		if(vboxdd_read(disk, (offset - over_off), tmp_buf, STD_SECTORSIZE) < 0)
			goto write_err_exit;
		tmp_count = STD_SECTORSIZE - over_off;
		if(count < tmp_count) tmp_count = count;
		memcpy((tmp_buf + over_off), buf, tmp_count); /* Write difference. */
		if(vboxdd_write(disk, (offset - over_off), tmp_buf, STD_SECTORSIZE) < 0)
			goto write_err_exit;
		buf = ((char *) buf) + (tmp_count);
		offset += tmp_count;
		until_count -= tmp_count;
	}
	/* Write all blocks contained in count. */
	if((tmp_count = (until_count & ~STD_SECTORSIZE_OFFSET_MASK))) {
		if(vboxdd_write(disk, offset, buf, tmp_count) < 0)
			goto write_err_exit;
		buf = ((char *) buf) + tmp_count;
		offset += tmp_count;
		until_count -= tmp_count;
	}
	if(until_count > 0) { /* until_count < blocksize */
		if(vboxdd_read(disk, offset, tmp_buf, STD_SECTORSIZE) < 0)
			goto write_err_exit;
		memcpy(tmp_buf, buf, until_count); /* Write difference. */
		if(vboxdd_write(disk, offset, tmp_buf, STD_SECTORSIZE) < 0)
			goto write_err_exit;
	}
	return count;
write_err_exit:
	errno = EIO; return -1;
}

static inline size_t _wrap_count(size_t size, off_t *offset, size_t count) {
	if(*offset > (off_t) size) *offset = size;
	if((*offset + count) > size) count = size - *offset;
	return count;
}

/******************************************************************************/
/***********************************SYSCALL************************************/

int vuvdi_open(const char *pathname, mode_t mode, struct vudevfd_t *vudevfd) {
	struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
  return vdi->fd;
}

int vuvdi_close(int fd, struct vudevfd_t *vudevfd) {
	struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
	vboxdd_flush(vdi->disk);
  return 0;
}

ssize_t vuvdi_pread(int fd, void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd) {
	struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
	//vudev_printd("offset [%lu] count [%d]", offset, count);
	count = _wrap_count(vdi->size, &offset, count);
	return _vuvdi_alined_pread64(vdi->disk, buf, count, offset);
}

ssize_t vuvdi_pwrite(int fd, const void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd) {
	struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
	//vudev_printd("offset [%lu] count [%d]", offset, count);
	count = _wrap_count(vdi->size, &offset, count);
	return _vuvdi_alined_pwrite64(vdi->disk, buf, count, offset);
}

off_t vuvdi_lseek(int fd, off_t offset, int whence, struct vudevfd_t *vudevfd) {
  off_t ret_value;
	switch (whence) {
		case SEEK_SET: ret_value = offset;
									 break;
		case SEEK_CUR: ret_value = (vudevfd->offset + offset);
									 break;
		case SEEK_END: {
										 struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
										 ret_value = vdi->size + offset;
										 break;
									 }
    default:
									 errno = EINVAL;
									 ret_value = (off_t) -1;
									 break;
	}
	return ret_value;
}

int vuvdi_ioctl(int fd, unsigned long request, void *addr, struct vudevfd_t *vudevfd){
	if (fd >= 0) {
		struct vuvdi_t *vdi = vudev_get_private_data(vudevfd->vudev);
		switch (request) {
			case BLKROGET:
				*(int *)addr = (vdi->flags & MS_RDONLY);
				break;
			case BLKROSET: {
											 vdi->flags |= (*(int *)addr > 0)? MS_RDONLY:0;
											 if(vboxdd_set_open_flags(vdi->disk, 0,
														 (vdi->flags&MS_RDONLY)? VD_OPEN_FLAGS_READONLY:VD_OPEN_FLAGS_NORMAL) < 0)
												 goto ioctl_err_exit;
											 break;
										 }
			case BLKSSZGET:
										 *(int *)addr = STD_SECTORSIZE;
										 break;
			case BLKGETSIZE:
										 *(int *)addr = vdi->size / STD_SECTORSIZE;
										 break;
			case BLKGETSIZE64:
										 *(long long *)addr = vdi->size;
										 break;
			case BLKRRPART: break;
			case HDIO_GETGEO: {
													struct {
														uint32_t cCylinders;
														uint32_t cHeads;
														uint32_t cSectors;
													} vdgeom;
													if(vboxdd_get_LCHS_geometry(vdi->disk, 0, &vdgeom) < 0)
														goto ioctl_err_exit;
													struct hd_geometry *hdg = addr;
													hdg->heads = (unsigned char) vdgeom.cHeads;
													hdg->sectors = (unsigned char) vdgeom.cSectors;
													hdg->cylinders = (unsigned short) vdgeom.cCylinders;
													hdg->start = 0;
													break;
												}
			default: ioctl_err_exit:
							 errno = EINVAL; return -1;
		}
		return 0;
	} else {
    return -1;
  }
}

static void *vuvdi_init(const char *source, unsigned long flags, const char *args, struct vudev_t *vudev) {
	struct vuvdi_t *vdi;
	char *disk_type = "auto";
	if (dlload_vboxdd() == -1)
		return NULL;
	if((vdi = calloc(1, sizeof(struct vuvdi_t))) == NULL)
		goto exit_err;
	if((vdi->fd = open(source, O_RDONLY)) == -1)
		goto exit_err;
	vdi->flags = flags;
	if(vboxdd_create(NULL, 0, &vdi->disk) < 0) {
		printk(KERN_ERR "invalid initialisation of VD interface\n");
		goto exit_err;
	}
	if(vboxdd_detect_type(vdi->fd, &disk_type) < 0)
		goto exit_err;
	if(vboxdd_open(vdi->disk, disk_type, source,
				(flags&MS_RDONLY)? VD_OPEN_FLAGS_READONLY:VD_OPEN_FLAGS_NORMAL, NULL) < 0) {
		errno = ENODEV;
		printk(KERN_ERR "opening vbox image failed\n");
		goto exit_err;
	}
	vdi->size = vboxdd_get_size(vdi->disk, 0);
	vudev_set_devtype(vudev, S_IFBLK);
	return vdi;
exit_err:
	dlunload_vboxdd();
	free(vdi);
	return NULL;
}

int vuvdi_fini(void *private_data) {
  struct vuvdi_t *vdi = private_data;
	if(vdi) {
		vboxdd_close(vdi->disk, 0); /* If true, delete the image from the host disk. */
		free(vdi);
	}
	dlunload_vboxdd();
	private_data = NULL;
	return 0;
}

struct vudev_operations_t vudev_ops = {
  .open = vuvdi_open,
  .close = vuvdi_close,
	.pread = vuvdi_pread,
	.pwrite = vuvdi_pwrite,
  .lseek = vuvdi_lseek,
  .ioctl = vuvdi_ioctl,
  .init = vuvdi_init,
  .fini = vuvdi_fini,
};
