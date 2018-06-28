#ifndef VUDEV_H
#define VUDEV_H
#include <sys/epoll.h>

struct vudev_t;

struct vudevfd_t {
  dev_t subdev;
	off_t offset;
  int flags;
  void *fdprivate;
  struct vudev_t *vudev;
};

void *vudev_get_private_data(struct vudev_t *vudev);
void vudev_set_devtype(struct vudev_t *vudev, mode_t devtype);

struct vudev_operations_t {
	int (*confirm_subdev) (int subdev, struct vudev_t *vudev);
  int (*open) (const char *pathname, mode_t mode, struct vudevfd_t *vdefd);
  int (*close) (int fd, struct vudevfd_t *vdefd);
  ssize_t (*read) (int fd, void *buf, size_t count, struct vudevfd_t *vdefd);
  ssize_t (*write) (int fd, const void *buf, size_t count, struct vudevfd_t *vdefd);
  ssize_t (*pread) (int fd, void *buf, size_t count, off_t offset, struct vudevfd_t *vdefd);
  ssize_t (*pwrite) (int fd, const void *buf, size_t count, off_t offset, struct vudevfd_t *vdefd);
  off_t (*lseek) (int fd, off_t offset, int whence, struct vudevfd_t *vdefd);
  int (*ioctl) (int fd,  unsigned long request, void *addr, struct vudevfd_t *vdefd);
  int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event, struct vudevfd_t *vdefd);
  void * (*init) (const char *source, unsigned long flags, const char *args, struct vudev_t *vudev);
  int (*fini) (void *private_data);
};

#endif


