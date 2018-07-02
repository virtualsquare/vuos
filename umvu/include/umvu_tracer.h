#ifndef UMVU_TRACER_H
#define UMVU_TRACER_H
#include <unistd.h>
#include <umvu_peekpoke.h>

typedef void (*syscall_handler_t)(syscall_state_t, struct syscall_descriptor_t *);

int umvu_tracer_fork(void);
int umvu_tracepid(pid_t childpid, syscall_handler_t syscall_handler_arg, int main);
#endif
