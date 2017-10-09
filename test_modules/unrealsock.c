#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <vumodule.h>
#include <errno.h>

VU_PROTOTYPES(unrealsock)

	struct vu_module_t vu_module = {
		.name = "unrealsock",
		.description = "unrealsock: tcp-ip stack server side"
	};

int vu_unrealsock_msocket(const char *path, int domain, int type, int protocol) {
	if (path != NULL) {
		errno = EINVAL;
		return -1;
	}
	return socket(domain, type, protocol);
}

static struct vuht_entry_t *ht[3];
static int afs[3] = {AF_INET, AF_INET6, AF_NETLINK};

void *vu_unrealsock_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	int i;

	vu_syscall_handler(s, bind) = bind;
	vu_syscall_handler(s, connect) = connect;
	vu_syscall_handler(s, listen) = listen;
	vu_syscall_handler(s, accept4) = accept4;
	vu_syscall_handler(s, getsockname) = getsockname;
	vu_syscall_handler(s, getpeername) = getpeername;
	vu_syscall_handler(s, sendto) = sendto;
	vu_syscall_handler(s, recvfrom) = recvfrom;
	vu_syscall_handler(s, shutdown) = shutdown;
	vu_syscall_handler(s, setsockopt) = setsockopt;
	vu_syscall_handler(s, getsockopt) = getsockopt;
	vu_syscall_handler(s, epoll_ctl) = epoll_ctl;
	vu_syscall_handler(s, close) = close;

	for (i = 0; i < 3; i++)
		ht[i] = vuht_add(CHECKSOCKET, &afs[i], sizeof(int), s, NULL, NULL, 0);
	return NULL;
}

void vu_unrealsock_fini(void *private) {
	int i;
	for (i = 0; i < 3; i++) {
		if (ht[i] && vuht_del(ht[i], 0) == 0)
			ht[i] = NULL;
	}
}
