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
 *   UMDEV: Virtual Device in Userspace
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <syscall_defs.h>
#include <syscall_table.h>
#include <vu_execute.h>
#include <epoch.h>
#include <hashtable.h>
#include <arch_table.h>
#include <path_utils.h>
#include <syscall_names.h>
#include <unistd.h>
#include <sys/syscall.h> 
#include <r_table.h>
#include <vu_log.h>
#include <vu_execute.h>
#include <vu_fs.h>
#include <xcommon.h>

struct vuht_entry_t *choice_NULL(struct syscall_descriptor_t *sd) {
	return NULL;
}

void wi_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	//printk("UNMANAGED %s\n", syscallname(sd->syscall_number));
}

void wd_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wo_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}

void vw_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}


static inline struct syscall_extra_t *set_extra(struct syscall_descriptor_t *sd,
		char *(*getpath)(struct syscall_descriptor_t *sd, struct vu_stat *buf)) {
	static __thread struct syscall_extra_t extra;
	extra.statbuf.st_mode = 0;
	/**The syscall may refer to a path. This path is canonicalized and saved so that it can be used 
		during che management of the call. It can be NULL.*/
	extra.path = getpath(sd, &extra.statbuf);
	extra.path_errno = errno;
	extra.nested = VU_NOT_NESTED;
	extra.epoch = get_vepoch();
	return &extra;
}

static inline void execute_cleanup (struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht != NULL)
		vuht_drop(ht);
	xfree(sd->extra->path);
}

void vu_syscall_execute(syscall_state_t state, struct syscall_descriptor_t *sd) {
	static __thread struct vuht_entry_t *ht;

	update_vepoch();
	if (sd->syscall_number >= 0) {
		int sysno = vu_arch_table[sd->orig_syscall_number];
		/**Depending on the sysno, it takes a structure where are stored some functions:
		choiche, wrap in, wrap during, wrap out. These functions act as wrappers to the system call allowing the virtualization.*/
		struct syscall_tab_entry *tab_entry = &vu_syscall_table[sysno];
		switch (state) {
			case IN_SYSCALL:
				sd->extra = set_extra(sd, get_syspath);

				printkdebug(s, "IN %d (%d) %d %s %s ", umvu_gettid(), native_syscall(__NR_gettid), sd->syscall_number,
						syscallname(sd->syscall_number),
						(sd->extra->path != NULL) ? sd->extra->path : "");
				
				/**Choosing the hash table element (the service module that will manage the syscall). It can be NULL.*/
				ht = tab_entry->choicef(sd);
				if (sd->action == SKIPIT)
					execute_cleanup(ht,sd);
				else {
					if (vu_fs_is_chroot())
						rewrite_syspath(sd, sd->extra->path); 
					tab_entry->wrapinf(ht, sd);
					if ((sd->action & UMVU_CB_AFTER) == 0)
						/**no more managed in DURING_SYSCALL or OUT_SYSCALL phase.*/ 
						execute_cleanup(ht,sd);
				}
				break;
			case DURING_SYSCALL:
				printkdebug(s, "DURING %d %s %s", umvu_gettid(), 
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapduringf(ht, sd);
				if ((sd->action & UMVU_CB_AFTER) == 0)
					execute_cleanup(ht,sd);
				break;
			case OUT_SYSCALL:
				printkdebug(s, "OUT %d %s %s", umvu_gettid(), 
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapoutf(ht, sd);
				execute_cleanup(ht,sd);
				break;
		}
	} else {
		/**umvu commands are managed like system calls, but with a negative sysno.
			The command is executed then the captured 'system call' is skipped.*/
		int vsysno = - sd->syscall_number;
		sd->ret_value = -ENOSYS;
		if (vsysno < VVU_NR_SYSCALLS) {
			struct vsyscall_tab_entry *tab_entry = &vvu_syscall_table[vsysno];
			sd->extra = set_extra(sd, get_vsyspath);
			ht = tab_entry->choicef(sd);
			tab_entry->wrapf(ht, sd);
		}
		sd->action = SKIPIT;
	}
}

__attribute__((constructor)) 
	static void init(void) {
		debug_set_name(s, "SYSCALL");
	}
