#ifndef VUDEV_H
#define VUDEV_H
#include <sys/epoll.h>

struct vudev_t;

struct vudevfd_t {
  dev_t subdev;
  int flags;
  void *fdprivate;
  struct vudev_t *vudev;
};

void *vudev_get_private_data(struct vudev_t *vudev);
void vudev_set_devtype(struct vudev_t *vudev, mode_t devtype);

struct vudev_operations_t {
	int (*confirm_subdev) (int subdev, struct vudev_t *vudev);
  int (*open) (const char *pathname, mode_t mode, struct vudevfd_t *vdefd);
  int (*close) (struct vudevfd_t *vdefd);
  ssize_t (*read) (struct vudevfd_t *vdefd, void *buf, size_t count);
  ssize_t (*write) (struct vudevfd_t *vdefd, const void *buf, size_t count);
  ssize_t (*pread) (struct vudevfd_t *vdefd, void *buf, size_t count, off_t offset);
  ssize_t (*pwrite) (struct vudevfd_t *vdefd, const void *buf, size_t count, off_t offset);
  off_t (*lseek) (struct vudevfd_t *vdefd, off_t offset, int whence);
  int (*ioctl) (struct vudevfd_t *vdefd,  unsigned long request, void *addr);
  int (*epoll_ctl) (int epfd, int op, struct vudevfd_t *vdefd, struct epoll_event *event);
  void * (*init) (const char *source, unsigned long flags, const char *args, struct vudev_t *vudev);
  int (*fini) (void *private_data);
};

#endif


