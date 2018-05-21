#ifndef _VUNET_H
#define _VUNET_H
#include <vumodule.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#ifndef S_IFSTACK
#define S_IFSTACK 0160000
#endif
#ifndef SOCK_DEFAULT
#define SOCK_DEFAULT 0
#endif

void *vunet_get_fdprivate(void);
void vunet_set_fdprivate(void *fdprivate);
void *vunet_get_private_data(void);

struct vunet_operations {
	int (*socket) (int, int, int);
	int (*bind) (int, const struct sockaddr *, socklen_t);
	int (*connect) (int, const struct sockaddr *, socklen_t);
	int (*listen) (int, int);
	int (*accept4) (int, struct sockaddr *, socklen_t *, int flags);
	int (*getsockname) (int, struct sockaddr *, socklen_t *);
	int (*getpeername) (int, struct sockaddr *, socklen_t *);
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	int (*setsockopt) (int, int, int, const void *, socklen_t);
	int (*getsockopt) (int, int, int, void *, socklen_t *);
	int (*shutdown) (int, int);
	int (*ioctl) (int, int, void *);
	int (*close) (int);
	int (*fcntl) (int, int, long);

	int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);

	int (*supported_domain) (int domain);
	int (*init) (const char *source, unsigned long flags, const char *args, void **private_data);
	int (*fini) (void *private_data);
};

#endif
