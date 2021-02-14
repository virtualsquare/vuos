#ifndef __UMVIEW_PTRACE_DEFS__
#define __UMVIEW_PTRACE_DEFS__

#include <stdio.h>
#include <pthread.h>

#include <sys/uio.h>
#include <sys/ptrace.h>
#include <r_table.h>

/* helpers for ptrace:
  P_* produce an error messsage if ptrace fails, and terminates the thread
  P_*_NODIE produce an error messsage if ptrace fails (and continue) */

#define PTRACE(action, tracee_tid, addr, data)                                 \
    if (r_ptrace(action, tracee_tid, addr, data) == -1) {                      \
        char errmsg[80];                                                       \
        snprintf(errmsg, 80, "%s line %d, ptrace", __FILE__, __LINE__);        \
        perror(errmsg);                                                        \
        pthread_exit(NULL);                                                    \
    }

#define PTRACE_NODIE(action, tracee_tid, addr, data)                           \
    if (r_ptrace(action, tracee_tid, addr, data) == -1) {                      \
        char errmsg[80];                                                       \
        snprintf(errmsg, 80, "%s line %d, ptrace", __FILE__, __LINE__);        \
        perror(errmsg);                                                        \
    }

#define P_GETREGS(tracee_tid, regs) \
  PTRACE(PTRACE_GETREGSET, tracee_tid, NT_PRSTATUS, &((struct iovec) {regs, sizeof(arch_regs_struct)}))
#define P_SETREGS(tracee_tid, regs) \
  PTRACE(PTRACE_SETREGSET, tracee_tid, NT_PRSTATUS, &((struct iovec) {regs, sizeof(arch_regs_struct)}))

#define P_SYSCALL(tracee_tid, signal) PTRACE(PTRACE_SYSCALL, tracee_tid, 0L, signal)
#define P_CONT(tracee_tid, signal) PTRACE(PTRACE_CONT, tracee_tid, 0L, signal)
#define P_LISTEN(tracee_tid, signal) PTRACE(PTRACE_LISTEN, tracee_tid, 0L, signal)
#define P_INTERRUPT(tracee_tid, signal)                                        \
    PTRACE(PTRACE_INTERRUPT, tracee_tid, 0L, signal)
#define P_ATTACH(tracee_tid, signal) PTRACE(PTRACE_ATTACH, tracee_tid, 0L, signal)
#define P_SEIZE(tracee_tid, signal) PTRACE(PTRACE_SEIZE, tracee_tid, 0L, signal)
#define P_DETACH(tracee_tid, signal) PTRACE(PTRACE_DETACH, tracee_tid, 0L, signal)
#define P_SETOPT(tracee_tid, opt) PTRACE(PTRACE_SETOPTIONS, tracee_tid, 0L, opt)
#define P_GETEVENTMSG(tracee_tid, event)                                       \
    PTRACE(PTRACE_GETEVENTMSG, tracee_tid, 0L, event)

#define P_GETREGS_NODIE(tracee_tid, regs)                                      \
  PTRACE_NODIE(PTRACE_GETREGSET, tracee_tid, NT_PRSTATUS,                      \
    &((struct iovec) {regs, sizeof(arch_regs_struct)}))
#define P_SETREGS_NODIE(tracee_tid, regs)                                      \
  PTRACE_NODIE(PTRACE_SETREGSET, tracee_tid, NT_PRSTATUS,                      \
    &((struct iovec) {regs, sizeof(arch_regs_struct)}))
#define P_SYSCALL_NODIE(tracee_tid, signal)                                    \
  PTRACE_NODIE(PTRACE_SYSCALL, tracee_tid, 0L, signal)
#define P_CONT_NODIE(tracee_tid, signal)                                       \
  PTRACE_NODIE(PTRACE_CONT, tracee_tid, 0L, signal)
#define P_DETACH_NODIE(tracee_tid, signal)                                     \
  PTRACE_NODIE(PTRACE_DETACH, tracee_tid, 0L, signal)
#define P_SEIZE_NODIE(tracee_tid, signal)                                      \
  PTRACE_NODIE(PTRACE_SEIZE, tracee_tid, 0L, signal)

#define PTRACE_STD_OPTS                                                        \
  PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC |             \
  PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |             \
  PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#endif
