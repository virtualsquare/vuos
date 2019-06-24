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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/uio.h>
#include <ptrace_defs.h>
#include <umvu_peekpoke.h>

/* pagesize/pagemask are useful to compute the page boundaries.
	 data tranfer operations are splitted in chunks, all the addresses
	 of a chunk belong to the same page */
/* pagesize/pagemask values are cached here at startup for performance
	 (these values cannnot change during the life of the hypervisor */
static unsigned long page_size;
static unsigned long page_mask;

/* tid of the "protected" process (each guardian angel controls
	 the virtualization of a user process/thread) */
static __thread unsigned int tracee_tid;

#if defined(__x86_64__)
void umvu_peek_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		peekpokeop_t op)
{
	if (regs && syscall_desc) {
		if (op == PEEK_ARGS) {
			syscall_desc->orig_syscall_number =
				syscall_desc->syscall_number = regs->orig_rax;
			syscall_desc->syscall_args[0] = regs->rdi;
			syscall_desc->syscall_args[1] = regs->rsi;
			syscall_desc->syscall_args[2] = regs->rdx;
			syscall_desc->syscall_args[3] = regs->r10;
			syscall_desc->syscall_args[4] = regs->r8;
			syscall_desc->syscall_args[5] = regs->r9;
			syscall_desc->prog_counter = regs->rip;
			syscall_desc->stack_pointer = regs->rsp;
		} else
			syscall_desc->orig_ret_value = regs->rax;
	}
}

int umvu_poke_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		peekpokeop_t op)
{
	if (regs && syscall_desc) {
		switch (op) {
			case POKE_ARGS:
				/* regs->rsp is missing as stack pointer should not be modified */
				if (regs->orig_rax == (unsigned) syscall_desc->syscall_number &&
						regs->rdi == syscall_desc->syscall_args[0] &&
						regs->rsi == syscall_desc->syscall_args[1] &&
						regs->rdx == syscall_desc->syscall_args[2] &&
						regs->r10 == syscall_desc->syscall_args[3] &&
						regs->r8 == syscall_desc->syscall_args[4] &&
						regs->r9 == syscall_desc->syscall_args[5] &&
						regs->rip == syscall_desc->prog_counter)
					return 0;
				regs->orig_rax = regs->rax = syscall_desc->syscall_number;
				regs->rdi = syscall_desc->syscall_args[0];
				regs->rsi = syscall_desc->syscall_args[1];
				regs->rdx = syscall_desc->syscall_args[2];
				regs->r10 = syscall_desc->syscall_args[3];
				regs->r8 = syscall_desc->syscall_args[4];
				regs->r9 = syscall_desc->syscall_args[5];
				regs->rip = syscall_desc->prog_counter;
				break;
			case POKE_RETVALUE:
				if (regs->rax == syscall_desc->ret_value)
					return 0;
				regs->rax = syscall_desc->ret_value;
				break;
			case SKIP_SETRETVALUE:
				regs->orig_rax = -1;
				regs->rax = syscall_desc->ret_value;
				break;
		}
		return 1;
	} else
		return 0;
}

#else

#error Unsupported architecture

#endif

void umvu_settid(pid_t tid) {
	tracee_tid = tid;
}

pid_t umvu_gettid()
{
	return tracee_tid;
}

void umvu_unblock(void) {
	P_INTERRUPT(tracee_tid, 0L);
}

void umvu_block(struct syscall_descriptor_t *sd) {
	sd->syscall_number = __NR_poll;
	sd->syscall_args[0] = 0;
	sd->syscall_args[1] = 0;
	sd->syscall_args[2] = -1;
}

/* return len or the offset of the next page boundary, whatever
	 is nearer to addr */
static inline long compute_chunk_len(uintptr_t addr, size_t len) {
	unsigned long chunk_len = len > page_size ? page_size : len;
	unsigned long end_in_page = ((uintptr_t)(addr + chunk_len) & page_mask);
	if (chunk_len > end_in_page) chunk_len -= end_in_page;
	return chunk_len;
}

int umvu_peek_str(uintptr_t addr, void *buf, size_t datalen)
{
	char *cbuf = buf;

	if (addr && cbuf) {
		/* transfer data, chunk by chunk */
		while (datalen > 0) {
			unsigned long chunk_len = compute_chunk_len(addr, datalen);
			struct iovec local_iov = {cbuf, chunk_len};
			struct iovec remote_iov = {(void *) addr, chunk_len};
			int rv=process_vm_readv(tracee_tid, &local_iov, 1, &remote_iov, 1, 0);
			if (rv != (int) chunk_len)
				return -1;
			else {
				unsigned int r;
				/* it is a string, when there is a NULL byte, the transfer is completed */
				for (r = 0; r < chunk_len; r++)
					if (cbuf[r] == 0)
						return 0;
				datalen -= chunk_len;
				addr += chunk_len;
				cbuf += chunk_len;
			}
		}
		cbuf[-1] = 0;
	}
	return 0;
}

char *umvu_peekdup_path(uintptr_t addr) {
	char path[PATH_MAX];
	if (umvu_peek_str(addr, path, PATH_MAX) == 0)
		return strdup(path);
	else
		return NULL;
}

int umvu_peek_data(uintptr_t addr, void *buf, size_t datalen)
{
	char *cbuf = buf;

	if (addr && cbuf) {
		/* transfer data, chunk by chunk */
		while (datalen > 0) {
			unsigned long chunk_len = compute_chunk_len(addr, datalen);
			struct iovec local_iov = {cbuf, chunk_len};
			struct iovec remote_iov = {(void *) addr, chunk_len};
			int rv=process_vm_readv(tracee_tid, &local_iov, 1, &remote_iov, 1, 0);
			if (rv != (int) chunk_len)
				return -1;
			else {
				datalen -= chunk_len;
				addr += chunk_len;
				cbuf += chunk_len;
			}
		}
	}
	return 0;
}

int umvu_poke_data(uintptr_t addr, void *buf, size_t datalen)
{
	if (addr && buf) {
		struct iovec local_iov = {buf, datalen};
		struct iovec remote_iov = {(void *) addr, datalen};
		return process_vm_writev(tracee_tid, &local_iov, 1, &remote_iov, 1, 0) >= 0;
	} else
		return 0;
}

unsigned long umvu_get_pagesize(void) {
	return page_size;
}

__attribute__((constructor))
	static void __init__(void) {
		page_size = sysconf(_SC_PAGESIZE);
		page_mask = page_size - 1;
	}
