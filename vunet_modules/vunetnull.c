#include <vunet.h>
#include <errno.h>

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

static int null_socket(int domain, int type, int protocol) {
	errno = EAFNOSUPPORT;
	return -1;
}

struct vunet_operations vunet_ops = {
	.socket = null_socket,

	.supported_domain = supported_domain,
};
