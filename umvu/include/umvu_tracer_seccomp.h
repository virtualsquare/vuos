#ifndef UMVU_TRACER_SECCOMP_H
#define UMVU_TRACER_SECCOMP_H
#include <unistd.h>
#include <umvu_peekpoke.h>

/* tracer: this is the lowest layer of virtualization */
typedef void (*syscall_handler_t)(syscall_state_t, struct syscall_descriptor_t *);

/* test if seccomp is available on the hosting system */
int umvu_tracer_test_seccomp(void);

/* the tracer must be used as follows:
 *      int wstatus;
 *      switch(childpid = umvu_tracer_fork_seccomp()) {
 *         case 0: .... root of the virtualized processes
 *                 exit(...)
 *         default: .... init the tracer
 *                 wstatus = umvu_tracepid_seccomp(childpid, syscall_hangler, 1);
 *                  .... cleanup tracer
 *                 exit(WEXITSTATUS(wstatus))
 *         case -1:
 *                 .... error management
 */
int umvu_tracer_fork_seccomp(void);
int umvu_tracepid_seccomp(pid_t childpid, syscall_handler_t syscall_handler_arg, int main);
#endif
