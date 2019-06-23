#ifndef UMVU_PEEKPOKE_H
#define UMVU_PEEKPOKE_H

/* umvu_peekpoke: exchange data with the traced/virtualized process */

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

/* STATES of syscall processing.
 * A syscall request process begins in IN_SYSCALL state.
 * The hypervisor pre-processes the request and can decide:
 * 	to ask the kernel to skip the request (the processing completes in IN_SYSCALL state)
 *		(this is the case of fully virtualized calls)
 *	to ask the kernel to process the request (the processing completes in IN_SYSCALL state)
 *		(this is the case of non virtualized calls)
 *	to ask the kernel to process the request and call again when the system call has completed
 *		in this case the syscall request next state is DURING_SYSCALL and then when
 *		the kernel has completed the final state becomes OUT_SYSCALL */

typedef enum syscall_state_t {
	IN_SYSCALL,
	DURING_SYSCALL,
	OUT_SYSCALL } syscall_state_t;

/* syscall peekpoke operations:
 * PEEKPOKE_ARGS: peek or poke all the syscall args
 *                syscall# args program_counter stack_pointer
 * PEEKPOKE_RETVALUE: peek or poke retvalue (or error)
 * SKIP_SETRETVALUE: skip the syscall and set the retvalue (seccomp only) */
typedef enum peekpokeop_t {
	PEEK_ARGS,
	POKE_ARGS=PEEK_ARGS,
	PEEK_RETVALUE,
	POKE_RETVALUE=PEEK_RETVALUE,
	SKIP_SETRETVALUE } peekpokeop_t;

#define UMVU_SKIP 0x1
#define UMVU_CB_AFTER 0x2
#define UMVU_BLOCKIT 0x4
#define UMVU_DO_IT_AGAIN 0x8

/* return codes for syscall_hadlers
	 (mapped as bitmaps of requests enabled  by that return code)
	 e.g. BLOCKIT implies UMVU_CB_AFTER */
typedef enum syscall_action_t {
	DOIT = 0,
	SKIPIT = UMVU_SKIP,
	DOIT_CB_AFTER = UMVU_CB_AFTER,
	BLOCKIT = UMVU_BLOCKIT | UMVU_CB_AFTER,
	DO_IT_AGAIN = UMVU_DO_IT_AGAIN
} syscall_action_t;

#define ACTION_STRINGS { \
	/* 0 */ "DOIT", \
	/* 1 */ "SKIPIT", \
	/* 2 */ "DOIT_CB_AFTER", \
	/* 3 */ "?", \
	/* 4 */ "?", \
	/* 5 */ "?", \
	/* 6 */ "BLOCKIT", \
	/* 7 */ "?", \
	/* 8 */ "DO_IT_AGAIN" \
	/* 9 */ "?", \
	/* A */ "?", \
	/* B */ "?", \
	/* C */ "?", \
	/* D */ "?", \
	/* E */ "?", \
	/* F */ "?"  }

struct syscall_extra_t;

/* system call descriptor --
	 all what a syscall handler need to know about a system call */
/* this structure is architecture independent */
struct syscall_descriptor_t {
	/* the action: default value = DOIT */
	syscall_action_t action;
	/* orig_syscall_number is the syscall requested by the user process.
		 syscall_number has a different value if the hypervisor requires the kernel
		 to process a different system call */
	int syscall_number;
	int orig_syscall_number;
	/* syscall arguments */
	syscall_arg_t syscall_args[SYSCALL_ARG_NR];
	/* the return value from the kernel */
	syscall_arg_t orig_ret_value;
	/* the return value returned to the user process */
	syscall_arg_t ret_value;
	/* instruction pointer/program counter of the syscall request */
	uintptr_t prog_counter;
	/* stack pointer */
	uintptr_t stack_pointer;
	/* pid of the watchdog process, to manage blocking calls
		 it is 0 when the watchdog process is not active */
	pid_t waiting_pid;
	/* pointer to further data required by the upper layers */
	struct syscall_extra_t *extra;
	/* opaque pointer used to exchange data between the phases of
		 syscall processing (IN_SYSCALL, DURING_SYSCALL, OUT_SYSCALL) */
	void *inout;
};

/* set/get the tid of the user process/thread controlled
	 by the current hypervisor thread.
	 (i.e. the "guarded"/"protected" thread of the current "guardian angel") */
void umvu_settid(pid_t tid);
pid_t umvu_gettid();

/* block the user process: it changes the syscall to poll(0, 0, -1) */
void umvu_block(struct syscall_descriptor_t *sd);
/* unblock the user process (using TRACE_INTERRUPT,
	 poll(0, 0, -1) returns -1/EINTR */
void umvu_unblock(void);

/* get the syscall info from PTRACE_GETREGS
	 this call is architecture dependent.
	 if op == PEEKPOKE_ARGS
	 get syscall_number, args, prog_counter, stack_pointer
	 otherwise (PEEKPOKE_RETVALUE)
	 get orig_ret_value
 */
void umvu_peek_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		peekpokeop_t op);

/* store the syscall into (prepaare it for PTRACE_SETREGS)
	 this call is architecture dependent.
	 The return value is > 0 if PTRACE_SETREGS is required
	 (some values changed). If teh return value is
	 0, PTRACE_SETREGS can be safely skipped.

	 if op == PEEKPOKE_ARGS:
	 store syscall_number, args, prog_counter.
	 if op == SKIP_SETRETVALUE:
	 store syscall_number and return value
	 else (PEEKPOKE_RETVALUE)
	 store just the return value.
 */
int umvu_poke_syscall(struct user_regs_struct *regs,
		struct syscall_descriptor_t *syscall_desc,
		peekpokeop_t op);

/* in all the following functions:
 * the identity of the user process is implicit as
 these functions are for guardian angels, each angel is
 assigned exactly one "protected" thread.
 * addr is the address in the user process memory area
 * buf is the local buffer
 */
/* get a string from a user process, i.e. get data up to the first
	 NULL byte (datalen is the max string length) */
int umvu_peek_str(uintptr_t addr, void *buf, size_t datalen);
/* get a string from a user process, the max length is PATH_MAX.
	 return a dynamic allocated copy of the string */
char *umvu_peekdup_path(uintptr_t addr);
/* get exactly datalen bytes from the user process memory */
int umvu_peek_data(uintptr_t addr, void *buf, size_t datalen);
/* store exactly datalen bytes from the user process memory */
int umvu_poke_data(uintptr_t addr, void *buf, size_t datalen);

unsigned long umvu_get_pagesize(void);

#endif

