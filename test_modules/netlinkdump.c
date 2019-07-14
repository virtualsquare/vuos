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

VU_PROTOTYPES(netlinkdump)

	struct vu_module_t vu_module = {
		.name = "netlinkdump",
		.description = "dump netlink messages"
	};

static struct vuht_entry_t *ht;

static void dump(const char *title, const uint8_t *data, size_t bufsize, ssize_t len) {
	ssize_t line, i;
	/* out format:
		 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		 01234567890123456789012345678901234567890123456789012345678901234
		 */
	char hexbuf[48];
	char charbuf[17];
	printk("%s size %zd len %zd:\n", title, bufsize, len);
	if (bufsize > 0 && len > 0) {
		for (line = 0; line < len; line += 16) {
			for (i = 0; i < 16; i++) {
				ssize_t pos = line + i;
				if (pos < len) {
					sprintf(hexbuf + (3 * i), "%02x ", data[pos]);
					charbuf[i] = data[pos] >= ' ' && data[pos] <= '~' ? data[pos] : '.';
				} else {
					sprintf(hexbuf + (3 * i), "   ");
					charbuf[i] = ' ';
				}
			}
			charbuf[i] = 0;
			printk("  %s %s\n", hexbuf, charbuf);
		}
	}
}

ssize_t vu_netlinkdump_sendto (int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen,
		void *msg_control, size_t msg_controllen, void *fdprivate) {
	ssize_t retval = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	dump("->", buf, len, retval);
	return retval;
}

ssize_t vu_netlinkdump_recvfrom (int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen,
		void *msg_control, size_t *msg_controllen, void *fdprivate) {
	ssize_t retval = recvfrom(sockfd, buf, len,flags, src_addr, addrlen);
	dump("<-", buf, len, retval);
	return retval;
}

void *vu_netlinkdump_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
	int family = AF_NETLINK;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, socket) = socket;
	vu_syscall_handler(s, bind) = bind;
	vu_syscall_handler(s, connect) = connect;
	vu_syscall_handler(s, listen) = listen;
	vu_syscall_handler(s, accept4) = accept4;
	vu_syscall_handler(s, getsockname) = getsockname;
	vu_syscall_handler(s, getpeername) = getpeername;
	vu_syscall_handler(s, setsockopt) = setsockopt;
	vu_syscall_handler(s, getsockopt) = getsockopt;
	vu_syscall_handler(s, epoll_ctl) = epoll_ctl;
	vu_syscall_handler(s, close) = close;
#pragma GCC diagnostic pop

	ht = vuht_add(CHECKSOCKET, &family, sizeof(int), s, NULL, NULL, 0);
	return NULL;
}

int vu_netlinkdump_fini(void *private) {
	vuht_del(ht, MNT_FORCE);
	return 0;
}
