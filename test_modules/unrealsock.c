/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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

static struct vuht_entry_t *ht[3];
static int afs[3] = {AF_INET, AF_INET6, AF_NETLINK};

void *vu_unrealsock_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	int i;

	vu_syscall_handler(s, socket) = socket;
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

int vu_unrealsock_fini(void *private) {
	int i;
	for (i = 0; i < 3; i++) {
		if (ht[i] && vuht_del(ht[i], MNT_FORCE) == 0)
			ht[i] = NULL;
	}
	return 0;
}
