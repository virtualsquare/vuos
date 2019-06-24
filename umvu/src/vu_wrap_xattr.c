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

void wi_lgetxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		uintptr_t valueaddr = sd->syscall_args[2];
		size_t size = sd->syscall_args[3];
		char *name;
		char *value = NULL;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fgetxattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		if (valueaddr > 0) vu_alloc_arg(valueaddr, value, size, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_lgetxattr)(sd->extra->mpath, name, value, size, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else {
			sd->ret_value = ret_value;
			if (ret_value > 0 && valueaddr > 0)
				vu_poke_arg(valueaddr, value, ret_value, nested);
		}
		vu_free_arg(value, nested);
	}
}

void wi_lsetxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		uintptr_t valueaddr = sd->syscall_args[2];
		size_t size = sd->syscall_args[3];
		int flags = sd->syscall_args[4];
		char *name;
		char *value;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fsetxattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		vu_alloc_peek_arg(valueaddr, value, size, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_lsetxattr)(sd->extra->mpath, name, value, size, flags, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else
			sd->ret_value = ret_value;
		vu_free_arg(value, nested);
	}
}

void wi_llistxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t listaddr = sd->syscall_args[1];
		size_t size = sd->syscall_args[2];
		char *list = NULL;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_flistxattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		if (listaddr > 0) vu_alloc_arg(listaddr, list, size, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_llistxattr)(sd->extra->mpath, list, size, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else {
			sd->ret_value = ret_value;
			if (ret_value > 0 && listaddr > 0)
				vu_poke_arg(listaddr, list, ret_value, nested);
		}
		vu_free_arg(list, nested);
	}
}

void wi_lremovexattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		char *name;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fremovexattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_lremovexattr)(sd->extra->mpath, name, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else
			sd->ret_value = ret_value;
	}
}
