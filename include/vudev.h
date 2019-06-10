#ifndef VUDEV_H
#define VUDEV_H
#include <sys/epoll.h>

/* header file for vudev submodules */

/* A vudev submodule must define a global non-static variable:

	 struct vudev_operations_t vudev_ops = {
	 ....
	 }
*/

struct vudev_t;

struct vudevfd_t {
  dev_t subdev;
	off_t offset;
  int flags;
  void *fdprivate;
  struct vudev_t *vudev;
};

/* get the private data of the driver (return value of "init") */
void *vudev_get_private_data(struct vudev_t *vudev);

/* set the device type (S_IFBLK or S_IFCHR)
	 S_IFCHR is the default value */
void vudev_set_devtype(struct vudev_t *vudev, mode_t devtype);

struct vudev_operations_t {
	/* confirm_function for devices with trailing numbers (e.g. hda1, hda2 etc)
		 return 1 if this submodule manages that subdevice */
	int (*confirm_subdev) (int subdev, struct vudev_t *vudev);
  int (*open) (const char *pathname, mode_t mode, struct vudevfd_t *vudevfd);
  int (*close) (int fd, struct vudevfd_t *vudevfd);
	/* when pread/pwrite are defined, read/write can be omitted. umdev translates
		 read/write/seek and keepstrack ofthe file position */
  ssize_t (*read) (int fd, void *buf, size_t count, struct vudevfd_t *vudevfd);
  ssize_t (*write) (int fd, const void *buf, size_t count, struct vudevfd_t *vudevfd);
  ssize_t (*pread) (int fd, void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd);
  ssize_t (*pwrite) (int fd, const void *buf, size_t count, off_t offset, struct vudevfd_t *vudevfd);
  off_t (*lseek) (int fd, off_t offset, int whence, struct vudevfd_t *vudevfd);
	/* ioctl:
	 * when fd == -1: return -1 if request already encodes dir and size (_IO/_IOR/_IOW/_IORX in ioctl.h.
	 *                otherwise return a fake request with the right dir and size
	 * when fd >= 0: run the ioctl */
  int (*ioctl) (int fd,  unsigned long request, void *addr, struct vudevfd_t *vudevfd);
	/* management of poll/select/blocking requests */
  int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event, struct vudevfd_t *vudevfd);
	/* constructor/destructor of the driver.
	 * the return value of init:
	 *   - can be retrieved by vudev_get_private_data()
	 *   - is the private_data argument of fini */
  void * (*init) (const char *source, unsigned long flags, const char *args, struct vudev_t *vudev);
  int (*fini) (void *private_data);
};

#endif


