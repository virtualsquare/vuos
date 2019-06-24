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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <linux_32_64.h>
#include <vu_log.h>
#include <r_table.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <path_utils.h>
#include <vu_fs.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <vu_wrapper_utils.h>

/* TODO XXX ioctl can be a blocking syscall.
	 ioctl should be changed to poll(NULL, 0, -1),
	 the call of module's ioctl should be in the "during" phase,
	 sending a PTRACE_INTERRUPT when done, and
	 the results must be stored in the "out" phase */
void wi_ioctl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		/* args */
		int fd = sd->syscall_args[0];
		unsigned long request = sd->syscall_args[1];
		uintptr_t addr = sd->syscall_args[2];
		unsigned long reqargs;
		int sfd;
		void *private = NULL;
		void *buf = NULL;
		int len;
		sd->action = SKIPIT;
		if (fd < 0) {
			sd->ret_value = -EBADF;
			return;
		}
		sfd = vu_fd_get_sfd(fd, &private, nested);
		/* module's ioctl returns the encoding of size and direction of the parameter i
		 if fd ==  -1 */
		/* modern ioctls have already size and direction encoded in their request argument,
			 so if the modules' call fails, reqargs gets the value of request */
		reqargs = service_syscall(ht, __VU_ioctl)(-1, request, NULL, addr, private);
		if (reqargs == (unsigned long) -1)
			reqargs = request;
		len = _IOC_SIZE(reqargs);
		if (len > 0)
			vu_alloc_arg(addr, buf, len, nested);
		if (reqargs & IOC_OUT)
			vu_peek_arg(addr, buf, len, nested);
		ret_value = service_syscall(ht, __VU_ioctl)(sfd, request, buf, addr, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			sd->ret_value = ret_value;
			if (reqargs & IOC_IN)
				vu_poke_arg(addr, buf, len, nested);
		}
		if (buf)
			vu_free_arg(buf, nested);
	}
}

