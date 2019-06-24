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

/* Nested virtualization support through module self-virtualization.
	 This source code uses libpurelibc */

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
#include <vu_thread_sd.h>

#define PURELIBC_LIB "libpurelibc.so"

/* self-virtualization syscall request capturing function. */
/* wrappers for nested vritualization are the same used by vu_execute.c */
static long int capture_nested_syscall(long int syscall_number, ...) {
	va_list ap;
	struct syscall_extra_t extra;
	struct syscall_descriptor_t sd = {.extra = &extra, .inout = NULL};
	struct vuht_entry_t *ht;
	int sysno = vu_arch_table[syscall_number];
	struct syscall_tab_entry *tab_entry = &vu_syscall_table[sysno];
	long int ret_value;
	struct syscall_descriptor_t *ssd = set_thread_sd(&sd);
	epoch_t e = get_vepoch();
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
	extra.path = get_nested_syspath(syscall_number, sd.syscall_args, &extra.statbuf, &extra.path_rewrite);
	extra.mpath = extra.path;
	extra.path_errno = errno;
	extra.nested = VU_NESTED;
	extra.ht = NULL;
	extra.epoch = get_vepoch();
	printkdebug(n, "IN %d (%d) %s %s %d epoch %ld", umvu_gettid(), native_syscall(__NR_gettid),
			syscallname(sd.syscall_number), extra.path, errno, e);
	ht = extra.ht = tab_entry->choicef(&sd);
	if (sd.action != SKIPIT)
		tab_entry->wrapinf(ht, &sd);
	if (sd.action != SKIPIT) {
		long orig_ret_value = native_syscall(syscall_number,
				sd.syscall_args[0],
				sd.syscall_args[1],
				sd.syscall_args[2],
				sd.syscall_args[3],
				sd.syscall_args[4],
				sd.syscall_args[5]);
		sd.orig_ret_value = (orig_ret_value == -1) ? -errno : orig_ret_value;
		if (sd.action == DOIT_CB_AFTER)
			tab_entry->wrapoutf(ht, &sd);
		else
			sd.ret_value = sd.orig_ret_value;
		sd.inout = NULL;
	}
	ret_value = sd.ret_value;
	if (ht != NULL)
		vuht_drop(ht);
	xfree(extra.path);
	set_thread_sd(ssd);
	set_vepoch(e);
	if (ret_value < 0) {
		errno = -ret_value;
		ret_value = -1;
	}
	return ret_value;
}

static long int capture_forward_syscall(long int syscall_number, ...) {
	syscall_arg_t syscall_args[SYSCALL_ARG_NR];
	va_list ap;
	va_start (ap, syscall_number);
	syscall_args[0]=va_arg(ap,long int);
	syscall_args[1]=va_arg(ap,long int);
	syscall_args[2]=va_arg(ap,long int);
	syscall_args[3]=va_arg(ap,long int);
	syscall_args[4]=va_arg(ap,long int);
	syscall_args[5]=va_arg(ap,long int);
	va_end(ap);
	//printk("capture_forward_syscall %d\n", syscall_number);
	return native_syscall(syscall_number,
			syscall_args[0],
			syscall_args[1],
			syscall_args[2],
			syscall_args[3],
			syscall_args[4],
			syscall_args[5]);
}

typedef long (*sfun)();

void vu_nesting_disable(void) {
	sfun (*_pure_start_p)();
	char *ld_preload = getenv("LD_PRELOAD");
	//printk("NESTINGDISABLE %d\n", native_syscall(__NR_gettid));
	if (ld_preload != NULL && strcmp(ld_preload, PURELIBC_LIB) == 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_pure_start_p = dlsym(RTLD_DEFAULT,"_pure_start");
#pragma GCC diagnostic pop
		if (_pure_start_p)
			native_syscall = _pure_start_p(capture_forward_syscall, 0);
	}
	unsetenv("LD_PRELOAD");
}

void vu_nesting_enable(void) {
	sfun (*_pure_start_p)();
	char *ld_preload = getenv("LD_PRELOAD");
	//printk("NESTINGENABLE %d\n", native_syscall(__NR_gettid));
	if (ld_preload != NULL && strcmp(ld_preload, PURELIBC_LIB) == 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_pure_start_p = dlsym(RTLD_DEFAULT,"_pure_start");
#pragma GCC diagnostic pop
		if (_pure_start_p) {
			printk(KERN_INFO "Purelibc found: nested virtualization enabled\n");
			native_syscall = _pure_start_p(capture_nested_syscall, 0);
		}
	}
}

void vu_nesting_init(int argc, char **argv) {
	char *ld_preload = getenv("LD_PRELOAD");
	/* continue if purelibc is loaded, otherwise add LD_PRELOAD to the
		 environment and reload the hypervisor by execv("/proc/self/exe", argv); */
	if (ld_preload != NULL && strcmp(ld_preload, PURELIBC_LIB) == 0) {
#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		_pure_start_p = dlsym(RTLD_DEFAULT,"_pure_start");
#pragma GCC diagnostic pop
		if (_pure_start_p) {
			printk(KERN_INFO "Purelibc found: nested virtualization enabled\n");
			native_syscall = _pure_start_p(capture_forward_syscall, 0);
		}
#endif
	} else {
		if (setenv("LD_PRELOAD", PURELIBC_LIB, 1) == 0) {
			execv("/proc/self/exe", argv);
		}
		printk(KERN_ERR "Purelibc cannot be loaded, option disabled\n");
	}
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(n, "NESTED");
	}
