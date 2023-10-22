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

#include <vu_log.h>
#include <service.h>
#include <vu_execute.h>
#include <vu_fs.h>
#include <vu_fd_table.h>
#include <vu_thread_sd.h>
#include <vumodule.h>

/* helper functions for modules */

pid_t vu_mod_gettid() {
	return umvu_gettid();
}

mode_t vu_mod_getumask(void) {
	return vu_fs_get_umask();
}

mode_t vu_mod_getmode() {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	return sd->extra->statbuf.st_mode;
}

struct vuht_entry_t *vu_mod_getht(void) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	return sd->extra->ht;
}

void vu_mod_setht(struct vuht_entry_t *ht) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	sd->extra->ht = ht;
}

/* modules are not aware of direct or nested calls */
int vu_mod_getsyscall_number(void) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	return sd->syscall_number;
}

syscall_arg_t vu_mod_getsyscall_arg(unsigned int narg) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	if (narg < 6)
		return sd->syscall_args[narg];
	else
		return 0;
}

void vu_mod_peek_str(void *addr, void *buf, size_t datalen) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	if (nested)
		strncpy(buf, addr, datalen);
	else
		umvu_peek_str((uintptr_t) addr, buf, datalen);
}

char *vu_mod_peekdup_path(void *addr) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	if (nested)
		return strdup(addr);
	else {
		char path[PATH_MAX];
		if (umvu_peek_str((uintptr_t) addr, path,  PATH_MAX) == 0)
			return strdup(path);
		else
			return NULL;
	}
}

void vu_mod_peek_data(void *addr, void *buf, size_t datalen) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	if (nested)
		memcpy(buf, addr, datalen);
	else
		umvu_peek_data((uintptr_t) addr, buf, datalen);
}

void vu_mod_poke_data(void *addr, void *buf, size_t datalen) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	if (nested)
		memcpy(addr, buf, datalen);
	else
		umvu_poke_data((uintptr_t) addr, buf, datalen);
}

int vu_mod_fd_get_sfd(int fd, void **fdprivate) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	return vu_fd_get_sfd(fd, fdprivate, nested);
}

struct vuht_entry_t *vu_mod_fd_get_ht(int fd) {
	struct syscall_descriptor_t *sd = get_thread_sd();
	fatal(sd);
	fatal(sd->extra);
	int nested = sd->extra->nested;
	struct vuht_entry_t *rv = vu_fd_get_ht(fd, nested);
	return rv;
}
