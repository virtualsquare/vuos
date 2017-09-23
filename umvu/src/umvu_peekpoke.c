#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/uio.h>
#include <ptrace_defs.h>
#include <umvu_peekpoke.h>

static unsigned long page_size;
static unsigned long page_mask;
static __thread unsigned int tracee_tid;

#if defined(__x86_64__)
void umvu_peek_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		syscall_state_t sys_state)
{
	if (regs && syscall_desc) {
		if (sys_state == IN_SYSCALL) {
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
		syscall_state_t sys_state)
{
	if (regs && syscall_desc) {
		if (sys_state == IN_SYSCALL) {
			if (regs->orig_rax == (unsigned) syscall_desc->syscall_number &&
					regs->rdi == syscall_desc->syscall_args[0] &&
					regs->rsi == syscall_desc->syscall_args[1] &&
					regs->rdx == syscall_desc->syscall_args[2] &&
					regs->r10 == syscall_desc->syscall_args[3] &&
					regs->r8 == syscall_desc->syscall_args[4] &&
					regs->r9 == syscall_desc->syscall_args[5] &&
					//regs->rsp == syscall_desc->stack_pointer &&  /* stack pointer should not be modified */
					regs->rip == syscall_desc->prog_counter)
				return 0;
			regs->orig_rax = regs->rax = syscall_desc->syscall_number;
			regs->rdi = syscall_desc->syscall_args[0];
			regs->rsi = syscall_desc->syscall_args[1];
			regs->rdx = syscall_desc->syscall_args[2];
			regs->r10 = syscall_desc->syscall_args[3];
			regs->r8 = syscall_desc->syscall_args[4];
			regs->r9 = syscall_desc->syscall_args[5];
			//regs->rsp = syscall_desc->stack_pointer;
			regs->rip = syscall_desc->prog_counter;
		} else {
			if (regs->rax == syscall_desc->ret_value)
				return 0;
			regs->rax = syscall_desc->ret_value;
		}
		return 1;
	} else
		return 0;
}

#else

#error Unsupported architecture

#endif

void umvu_settid(int tid) {
	tracee_tid = tid;
}

unsigned int umvu_gettid()
{
	return tracee_tid;
}

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
		while (datalen > 0) {
			unsigned long chunk_len = compute_chunk_len(addr, datalen);
			struct iovec local_iov = {cbuf, chunk_len};
			struct iovec remote_iov = {(void *) addr, chunk_len};
			int rv=process_vm_readv(tracee_tid, &local_iov, 1, &remote_iov, 1, 0);
			if (rv != (int) chunk_len) 
				return -1;
			else {
				unsigned int r;
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
