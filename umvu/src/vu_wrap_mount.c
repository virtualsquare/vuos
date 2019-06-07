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

#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <xcommon.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <path_utils.h>

void wi_mount(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht && !nested) {
		/* standard args */
		int ret_value;
		/* args */
		char *source = umvu_peekdup_path(sd->syscall_args[0]);
		char *target = sd->extra->path;
		char *filesystemtype = umvu_peekdup_path(sd->syscall_args[2]);
		unsigned long mountflags = sd->syscall_args[3];
		char *data = NULL;
		if (sd->syscall_args[4] != 0)
			data = umvu_peekdup_path(sd->syscall_args[4]);
		/* fetch args */
		/* call */
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_mount)(source, target, filesystemtype, mountflags, data);
		xfree(source);
		xfree(filesystemtype);
		xfree(data);
		/* store results */
		if (ret_value < 0) 
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

void wi_umount2(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht && !nested) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		char *target = sd->extra->path;
		int flags;
		/* fetch args */
		switch (syscall_number) {
#ifdef __NR_umount
			case __NR_umount: flags = 0;
												break;
#endif
			case __NR_umount2: flags = sd->syscall_args[1];
												 break;
		}
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_umount2)(target, flags);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

