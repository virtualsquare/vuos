#include <vunet.h>

static int supported_domain (int domain) {
	switch (domain) {
		case AF_INET:
		case AF_INET6:
		case AF_NETLINK:
		case AF_PACKET:
			return 1;
		default:
			return 0;
	}
}

struct vunet_operations vunet_ops = {
	.socket = socket,
	.bind = bind,
	.connect = connect,
	.listen = listen,
	.accept4 = accept4,
	.getsockname = getsockname,
	.getpeername = getpeername,
	.recvmsg = recvmsg,
	.sendmsg = sendmsg,
	.getsockopt = getsockopt,
	.setsockopt = setsockopt,
	.shutdown = shutdown,
	.ioctl = ioctl,
	.close = close,

	.epoll_ctl = epoll_ctl,

	.supported_domain = supported_domain,
};
