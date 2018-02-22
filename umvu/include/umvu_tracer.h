#ifndef UMVU_TRACER_H
#define UMVU_TRACER_H
#include <unistd.h>
#include <umvu_peekpoke.h>

typedef enum inheritance_state_t {
	INH_CLONE,
	INH_START,
	INH_EXEC,
	INH_TERMINATE
} inheritance_state_t;

typedef void (*syscall_handler_t)(syscall_state_t, struct syscall_descriptor_t *);
typedef void *(*inheritance_upcall_t)(inheritance_state_t, void *);

int umvu_tracer_fork(void);
int umvu_tracepid(pid_t childpid, syscall_handler_t syscall_handler_arg, int main);

/**Some files constructor like use this function to register their specific inheritance_upcall_t function.
	Each file in their registered function performs a specific action according to the inheritance_state_t.*/
void umvu_inheritance_upcall_register(inheritance_upcall_t upcall);

#endif
