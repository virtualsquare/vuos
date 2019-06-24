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
#include <errno.h>
#include <stdlib.h>
#include <syscall_defs.h>
#include <syscall_table.h>
#include <vu_execute.h>
#include <epoch.h>
#include <vu_thread_sd.h>
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

static char *action_strings[] = ACTION_STRINGS;
struct vuht_entry_t *choice_NULL(struct syscall_descriptor_t *sd) {
	return NULL;
}

/* default (dummy) wrappers */
void wi_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	//printk("UNMANAGED %s\n", syscallname(sd->syscall_number));
}

void wd_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

/* a dummy output wrappermust copy the return value */
void wo_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}

/* default wrapper for virtual system calls */
void vw_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

/* set the syscall_extra_t sturcture fields */
static inline void set_extra (
		struct syscall_extra_t *extra,
		struct syscall_descriptor_t *sd,
		char *(*getpath)(struct syscall_descriptor_t *sd, struct vu_stat *buf, uint8_t *need_rewrite)) {
	extra->statbuf.st_mode = 0;
	extra->path = getpath(sd, &extra->statbuf, &extra->path_rewrite);
	extra->mpath = extra->path;
	extra->path_errno = errno;
	extra->nested = VU_NOT_NESTED;
	extra->ht = NULL;
	extra->epoch = get_vepoch();
}

static inline void execute_cleanup (struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht != NULL)
		vuht_drop(ht);
	xfree(sd->extra->path);
}

/* vu_syscall_execute dispatches the syscall requests to the modules */
void vu_syscall_execute(syscall_state_t state, struct syscall_descriptor_t *sd) {
	static __thread struct syscall_extra_t extra;
	struct vuht_entry_t *ht;
	struct syscall_descriptor_t *ssd;

	update_vepoch();
	sd->extra = &extra;
	ssd = set_thread_sd(sd);
	if (sd->syscall_number >= 0) {
		int sysno = vu_arch_table[sd->orig_syscall_number];
		struct syscall_tab_entry *tab_entry = &vu_syscall_table[sysno];
		switch (state) {
			case IN_SYSCALL:
				set_extra(&extra, sd, get_syspath);
				printkdebug(s, "IN %d (%d) %s %s %ld", umvu_gettid(), native_syscall(__NR_gettid),
						syscallname(sd->syscall_number), sd->extra->path, get_vepoch());
				ht = sd->extra->ht = tab_entry->choicef(sd);
				if (sd->action == SKIPIT)
					execute_cleanup(ht,sd);
				else {
					if (vu_fs_is_chroot() || sd->extra->path_rewrite)
						rewrite_syspath(sd, sd->extra->path);
					tab_entry->wrapinf(ht, sd);
					if ((sd->action & UMVU_CB_AFTER) == 0)
						execute_cleanup(ht,sd);
				}
				printkdebug(a,"IN %s", action_strings[sd->action % 0xf]);
				break;
			case DURING_SYSCALL:
				ht = sd->extra->ht;
				printkdebug(s, "DURING %d %s %s", umvu_gettid(),
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapduringf(ht, sd);
				printkdebug(a,"DURING %s", action_strings[sd->action % 0xf]);
				if ((sd->action & UMVU_CB_AFTER) == 0)
					execute_cleanup(ht,sd);
				break;
			case OUT_SYSCALL:
				ht = sd->extra->ht;
				printkdebug(s, "OUT %d %s %s", umvu_gettid(),
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapoutf(ht, sd);
				execute_cleanup(ht,sd);
				break;
		}
	} else {
		int vsysno = - sd->syscall_number;
		sd->ret_value = -ENOSYS;
		if (vsysno < VVU_NR_SYSCALLS) {
			struct vsyscall_tab_entry *tab_entry = &vvu_syscall_table[vsysno];
			set_extra(&extra, sd, get_vsyspath);
			printkdebug(s, "VIRSYSCALL %d (%d) %d %s %ld", umvu_gettid(), native_syscall(__NR_gettid),
					vsysno, sd->extra->path, get_vepoch());
			ht = sd->extra->ht = tab_entry->choicef(sd);
			tab_entry->wrapf(ht, sd);
		}
		sd->action = SKIPIT;
	}
	set_thread_sd(ssd);
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(s, "SYSCALL");
		debug_set_name(a, "ACTION");
	}
