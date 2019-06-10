#ifndef _VUNET_H
#define _VUNET_H
#include <vumodule.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>

/* header file for vunet submodules */

/* A vunet submodule must define a global non-static variable:

   struct vunet_operations_t vunet_ops = {
   ....
   }
*/

#ifndef S_IFSTACK
#define S_IFSTACK 0160000
#endif
#ifndef SOCK_DEFAULT
#define SOCK_DEFAULT 0
#endif

/* set and get private data of a fd */
void *vunet_get_fdprivate(void);
void vunet_set_fdprivate(void *fdprivate);
/* get the private_data of the stack (set by init below) */
void *vunet_get_private_data(void);

struct vunet_operations {
	int (*socket) (int, int, int);
	int (*bind) (int, const struct sockaddr *, socklen_t);
	int (*connect) (int, const struct sockaddr *, socklen_t);
	int (*listen) (int, int);
	int (*accept4) (int, struct sockaddr *, socklen_t *, int flags);
	int (*getsockname) (int, struct sockaddr *, socklen_t *);
	int (*getpeername) (int, struct sockaddr *, socklen_t *);
	/* read, recv, recvfrom, recvmsg are all converted in recvmsg */
	ssize_t (*recvmsg)(int, struct msghdr *, int);
	/* write, send, sendto, sendmsg are all converted in sendmsg */
	ssize_t (*sendmsg)(int, const struct msghdr *, int);
	int (*setsockopt) (int, int, int, const void *, socklen_t);
	int (*getsockopt) (int, int, int, void *, socklen_t *);
	int (*shutdown) (int, int);
	/* ioctl:
	 * when fd == -1: return -1 if request already encodes dir and size (_IO/_IOR/_IOW/_IORX in ioctl.h.
	 *                otherwise return a fake request with the right dir and size
	 * when fd >= 0: run the ioctl */
	int (*ioctl) (int, unsigned long, void *);
	int (*close) (int);
	int (*fcntl) (int, int, long);

	/* management of poll/select/blocking requests */
	int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);

	/* return 1 if the submodule supports the address family, 0 otherwise */
	int (*supported_domain) (int domain);
	/* return 1 if the submodule supports the ioctl request, 0 otherwise */
	int (*supported_ioctl) (unsigned long request);

	/* constructor/destructor of the stack.
	 *	 *private_data in init:
	 *   - can be retrieved by vunet_get_private_data()
	 *   - is the private_data argument of fini */
	int (*init) (const char *source, unsigned long flags, const char *args, void **private_data);
	int (*fini) (void *private_data);
};

/* helper functions for ioctl:
 * vunet_is_netdev_ioctl returns a boolean: 1 (true) if the request is a netdevice ioctl (see netdevice(7)).
 * vunet_ioctl_parms convert network related requests in dir/size.
 *   (netdevice ioctl, FIONREAD, FIONBIO use an old ancoding which do not encode dir/size. */
int vunet_is_netdev_ioctl(unsigned long request);
long vunet_ioctl_parms(unsigned long request);

#endif
