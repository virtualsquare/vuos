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
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <syscall_defs.h>
#include <xcommon.h>
#include <hashtable.h>
#include <service.h>
#include <epoch.h>
#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <vu_wrapper_utils.h>
#include <vu_execute.h>

void wi_capget(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	uintptr_t hdrp = sd->syscall_args[0];
	uintptr_t datap = sd->syscall_args[1];
	cap_user_header_t hdr;
	cap_user_data_t data;
	sd->action = SKIPIT;
	if (hdrp == 0) {
		sd->ret_value = -EFAULT;
		return;
	}
	vu_alloc_peek_local_arg(hdrp, hdr, sizeof(*hdr), nested);
	if (hdr->version != _LINUX_CAPABILITY_VERSION_3) {
		sd->ret_value = -EFAULT;
		hdr->version = _LINUX_CAPABILITY_VERSION_3;
		vu_poke_arg(hdrp, hdr, sizeof(*hdr), nested);
		return;
	}
	if (datap == 0) {
		sd->ret_value = 0;
    return;
  }
	vu_alloc_local_arg(datap, data,
			sizeof(*data) * _LINUX_CAPABILITY_U32S_3, nested);
	if (ht) {
		sd->ret_value = service_syscall(ht, __VU_capget)(hdr, data);
	} else {
		sd->ret_value = capget(hdr, data);
	}
	if (sd->ret_value == 0)
		vu_poke_arg(datap, data,
				sizeof(*data) * _LINUX_CAPABILITY_U32S_3, nested);
}

void wi_capset(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		uintptr_t hdrp = sd->syscall_args[0];
		uintptr_t datap = sd->syscall_args[1];
		cap_user_header_t hdr;
		cap_user_data_t data;
		sd->action = SKIPIT;
		if (hdrp == 0) {
			sd->ret_value = -EFAULT;
			return;
		}
		vu_alloc_peek_local_arg(hdrp, hdr, sizeof(*hdr), nested);
		if (hdr->version != _LINUX_CAPABILITY_VERSION_3) {
			sd->ret_value = -EFAULT;
			hdr->version = _LINUX_CAPABILITY_VERSION_3;
			vu_poke_arg(hdrp, hdr, sizeof(*hdr), nested);
			return;
		}
		if (datap == 0) {
			sd->ret_value = 0;
			return;
		}
		if (hdr->pid == 0)
			hdr->pid = umvu_gettid();
		else if (hdr->pid != umvu_gettid()) {
			sd->ret_value = -EPERM;
			return;
		}
		vu_alloc_peek_local_arg(datap, data,
				sizeof(*data) * _LINUX_CAPABILITY_U32S_3, nested);
		sd->ret_value = service_syscall(ht, __VU_capset)(hdr, data);
	}
}
