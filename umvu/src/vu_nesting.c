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
#include <stdlib.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>

#include <xcommon.h>
#include <hashtable.h>
#include <r_table.h>
#include <syscall_names.h>
#include <syscall_table.h>
#include <arch_table.h>
#include <vu_log.h>
#include <vu_execute.h>
#include <path_utils.h>
#include <epoch.h>

#define PURELIBC_LIB "libpurelibc.so"

static long int capture_nested_syscall(long int syscall_number, ...) {
	va_list ap;
	struct syscall_descriptor_t sd;
	struct syscall_extra_t extra;
	struct vuht_entry_t *ht;
	int sysno = vu_arch_table[syscall_number];
	struct syscall_tab_entry *tab_entry = &vu_syscall_table[sysno];
	long int ret_value;
	epoch_t e = get_vepoch();
	sd.extra = &extra;
	sd.orig_syscall_number = 
		sd.syscall_number = syscall_number;
	va_start (ap, syscall_number);
	sd.syscall_args[0]=va_arg(ap,long int);
	sd.syscall_args[1]=va_arg(ap,long int);
	sd.syscall_args[2]=va_arg(ap,long int);
	sd.syscall_args[3]=va_arg(ap,long int);
	sd.syscall_args[4]=va_arg(ap,long int);
	sd.syscall_args[5]=va_arg(ap,long int);
	va_end(ap);
	sd.action = DOIT;
	sd.ret_value = 0;
	extra.statbuf.st_mode = 0;
	extra.path = get_nested_syspath(syscall_number, sd.syscall_args, &extra.statbuf);
	extra.path_errno = errno;
	extra.nested = VU_NESTED;
	extra.epoch = get_vepoch();
	printkdebug(n, "IN %s %s %d epoch %ld", syscallname(sd.syscall_number), extra.path, errno, e);
	ht = tab_entry->choicef(&sd);
	/**The nested management is similar to the not nested, but generally the call is not further virtualized
	and it is straight executed. */
	if (sd.action != SKIPIT)
		tab_entry->wrapinf(ht, &sd);
	if (sd.action != SKIPIT) {
		sd.orig_ret_value = native_syscall(syscall_number,
				sd.syscall_args[0],
				sd.syscall_args[1],
				sd.syscall_args[2],
				sd.syscall_args[3],
				sd.syscall_args[4],
				sd.syscall_args[5]);
		if (sd.action == DOIT_CB_AFTER)
			tab_entry->wrapoutf(ht, &sd);
		else
			sd.ret_value = sd.orig_ret_value;
	}
	ret_value =  sd.ret_value;
	if (ht != NULL)
		vuht_drop(ht);
	xfree(extra.path);
	set_vepoch(e);
	return ret_value;
}

typedef long (*sfun)();

#pragma GCC diagnostic ignored "-Wpedantic"
void vu_nesting_init(int argc, char *argv) {
	sfun (*_pure_start_p)();
	char *ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL && strcmp(ld_preload, PURELIBC_LIB) == 0) {
		_pure_start_p = dlsym(RTLD_DEFAULT,"_pure_start");
		if (_pure_start_p) {
			printk(KERN_INFO "Purelibc found: nested virtualization enabled\n");
			/**purelibc implementation of the calls will be used.
			 r_syscall will be considered nested and managed by capture_nested_syscall.*/
			native_syscall = _pure_start_p(capture_nested_syscall, 0);
		}

	} else {
		/**Setting the env variable and re-executing umvu.*/
		if (setenv("LD_PRELOAD", PURELIBC_LIB, 1) == 0) {
			execv("/proc/self/exe", argv);
		}
	}
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(n, "NESTED");
	}

