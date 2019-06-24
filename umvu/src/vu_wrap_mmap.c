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
#include <fcntl.h>
#include <ctype.h>

#include <linux_32_64.h>
#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <vu_wrapper_utils.h>
#include <vu_fnode_copy.h>
#include <vu_mmap_table.h>

void wi_mmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int fd = sd->syscall_args[4];
	int nested = sd->extra->nested;
	if (ht && fd >= 0) { // nothing to do if the file is real or is not a mmap on a file
		struct vu_fnode_t *fnode = vu_fd_get_fnode(fd, nested);
		vu_fnode_copyin(fnode);
		sd->inout = fnode;
		sd->action = DOIT_CB_AFTER;
	}
}

void wo_mmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct vu_fnode_t *fnode = sd->inout;
	if (fnode != NULL) {
		uintptr_t addr = sd->orig_ret_value;
		if (addr != (uintptr_t) -1) {
			size_t length = sd->syscall_args[1];
			__attribute__((unused)) int prot = sd->syscall_args[2];
			__attribute__((unused)) int flags = sd->syscall_args[3];
			off_t offset = sd->syscall_args[5];
#ifdef __NR_mmap2
			if (sd->syscall_number == __NR_mmap2)
				offset = offset * umvu_get_pagesize();
#endif
			vu_mmap_mmap(addr, length, fnode, offset);
			//printk("mmap %x %d %d %p\n", addr, length, offset, fnode);
		} else
			vu_fnode_close(fnode);
	}
	sd->ret_value = sd->orig_ret_value;
}

void wi_mm_cb_after(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->action = DOIT_CB_AFTER;
}

void wo_munmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
	if (sd->ret_value != (uintptr_t) -1) {
		uintptr_t addr = sd->syscall_args[0];
		size_t length = sd->syscall_args[1];
		vu_mmap_munmap(addr, length);
	}
}

void wo_mremap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	uintptr_t newaddr = sd->orig_ret_value;
	if (newaddr != (uintptr_t) -1) {
		uintptr_t oldaddr = sd->syscall_args[0];
		size_t oldlength = sd->syscall_args[1];
		size_t newlength = sd->syscall_args[2];
		vu_mmap_mremap(oldaddr, oldlength, newaddr, newlength);
	}
	sd->ret_value = sd->orig_ret_value;
}

void wo_msync(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}
