#ifndef __UMVIEW_PTRACE_DEFS__
#define __UMVIEW_PTRACE_DEFS__

#include <stdio.h>
#include <pthread.h>
#include <vu_log.h>

#include <sys/ptrace.h>
#include <r_table.h>

/* helpers for ptrace:
	P_* produce an error messsage if ptrace fails, and terminates the thread
	P_*_NODIE produce an error messsage if ptrace fails (and continue) */

#define PTRACE(action, tracee_tid, data)                                   \
	if (r_ptrace(action, tracee_tid, 0L, data) == -1) {                      \
		warning_msg("PTRACE");                                                 \
		pthread_exit(NULL);                                                    \
	}

#define PTRACE_NODIE(action, tracee_tid, data)                             \
	if (r_ptrace(action, tracee_tid, 0L, data) == -1) {                      \
		warning_msg("PTRACE");                                                 \
	}

#define P_GETREGS(tracee_tid, regs) PTRACE(PTRACE_GETREGS, tracee_tid, regs)
#define P_SETREGS(tracee_tid, regs) PTRACE(PTRACE_SETREGS, tracee_tid, regs)
#define P_SYSCALL(tracee_tid, signal) PTRACE(PTRACE_SYSCALL, tracee_tid, signal)
#define P_CONT(tracee_tid, signal) PTRACE(PTRACE_CONT, tracee_tid, signal)
#define P_LISTEN(tracee_tid, signal) PTRACE(PTRACE_LISTEN, tracee_tid, signal)
#define P_INTERRUPT(tracee_tid, signal)                                    \
	PTRACE(PTRACE_INTERRUPT, tracee_tid, signal)
#define P_ATTACH(tracee_tid, signal) PTRACE(PTRACE_ATTACH, tracee_tid, signal)
#define P_SEIZE(tracee_tid, signal) PTRACE(PTRACE_SEIZE, tracee_tid, signal)
#define P_DETACH(tracee_tid, signal) PTRACE(PTRACE_DETACH, tracee_tid, signal)
#define P_SETOPT(tracee_tid, opt) PTRACE(PTRACE_SETOPTIONS, tracee_tid, opt)
#define P_GETEVENTMSG(tracee_tid, event)                                   \
	PTRACE(PTRACE_GETEVENTMSG, tracee_tid, event)
#define P_PEEKDATA(tracee_tid, addr)                                       \
	r_ptrace(PTRACE_PEEKDATA, tracee_tid, (void *)addr, 0L)
#define P_POKEDATA(tracee_tid, addr, data)                                 \
	r_ptrace(PTRACE_POKEDATA, tracee_tid, (void *)addr, data)

#define P_GETREGS_NODIE(tracee_tid, regs)                                  \
	PTRACE_NODIE(PTRACE_GETREGS, tracee_tid, regs)
#define P_SETREGS_NODIE(tracee_tid, regs)                                  \
	PTRACE_NODIE(PTRACE_SETREGS, tracee_tid, regs)
#define P_SYSCALL_NODIE(tracee_tid, signal)                                \
	PTRACE_NODIE(PTRACE_SYSCALL, tracee_tid, signal)
#define P_DETACH_NODIE(tracee_tid, signal)                                 \
	PTRACE_NODIE(PTRACE_DETACH, tracee_tid, signal)
#define P_SEIZE_NODIE(tracee_tid, signal)                                  \
	PTRACE_NODIE(PTRACE_SEIZE, tracee_tid, signal)

#define PTRACE_STD_OPTS                                                    \
	PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC |         \
	PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |         \
	PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#endif
