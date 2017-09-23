#ifndef UMVU_PEEKPOKE_H
#define UMVU_PEEKPOKE_H

/*Architecture dependent part*/
#if defined(__x86_64__) || defined(__i386__)

#define SYSCALL_ARG_NR 6
typedef unsigned long int syscall_arg_t;
#define SYSCALL_INSTRUCTION_LEN 2

#else

#error Unsupported architecture

#endif

#include <sys/user.h>
#include <sys/types.h>
#include <stdint.h>

/* helper Macros */
#define SYSARG(type, sd, i) (type) sd->syscall_args[i]
#define SET_SYSARG(sd, i, val) sd->syscall_args[i] = (syscall_arg_t)val;

typedef enum syscall_state_t { 
	IN_SYSCALL, 
	DURING_SYSCALL,
	OUT_SYSCALL } syscall_state_t;

typedef enum syscall_action_t {
	DOIT,
	SKIP,
	DOIT_CB_AFTER
} syscall_action_t;

struct syscall_extra_t;

struct syscall_descriptor_t {
	syscall_action_t action;
	int syscall_number;
	int orig_syscall_number;
	syscall_arg_t syscall_args[SYSCALL_ARG_NR];
	syscall_arg_t orig_ret_value;
	syscall_arg_t ret_value;
	uintptr_t prog_counter;
	uintptr_t stack_pointer;
	struct syscall_extra_t *extra;
	void *inout;
};

void umvu_settid(int tid);
unsigned int umvu_gettid();

void umvu_peek_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		syscall_state_t sys_state);
int umvu_poke_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		syscall_state_t sys_state);

int umvu_peek_str(uintptr_t addr, void *buf, size_t datalen);
char *umvu_peekdup_path(uintptr_t addr);
int umvu_peek_data(uintptr_t addr, void *buf, size_t datalen);
int umvu_poke_data(uintptr_t addr, void *buf, size_t datalen);

unsigned long umvu_get_pagesize(void);

#endif

