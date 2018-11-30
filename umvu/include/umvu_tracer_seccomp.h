#ifndef UMVU_TRACER_SECCOMP_H
#define UMVU_TRACER_SECCOMP_H
#include <unistd.h>
#include <umvu_peekpoke.h>

typedef void (*syscall_handler_t)(syscall_state_t, struct syscall_descriptor_t *);

int umvu_tracer_fork_seccomp(void);
int umvu_tracepid_seccomp(pid_t childpid, syscall_handler_t syscall_handler_arg, int main);
#endif
