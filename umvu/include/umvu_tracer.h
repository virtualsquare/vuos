#ifndef UMVU_TRACER_H
#define UMVU_TRACER_H
#include <unistd.h>
#include <umvu_peekpoke.h>

/* tracer: this is the lowest layer of virtualization */
/* legacy implementation.
	 umvu_tracer_seccomp uses seccomp (BPF) to speedup the tracing */

typedef void (*syscall_handler_t)(syscall_state_t, struct syscall_descriptor_t *);

/* the tracer must be used as follows:
 *      int wstatus;
 *      switch(childpid = umvu_tracer_fork()) {
 *         case 0: .... root of the virtualized processes
 *                 exit(...)
 *         default: .... init the tracer
 *                 wstatus = umvu_tracepid(childpid, syscall_hangler, 1);
 *                  .... cleanup tracer
 *                 exit(WEXITSTATUS(wstatus))
 *         case -1:
 *                 .... error management
 */
int umvu_tracer_fork(void);
int umvu_tracepid(pid_t childpid, syscall_handler_t syscall_handler_arg, int main);
#endif
