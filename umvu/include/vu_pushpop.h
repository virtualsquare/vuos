#ifndef VU_PUSHPOP_H
#define VU_PUSHPOP_H
#include <umvu_peekpoke.h>

/* push and pop data on the user process stack. */

syscall_arg_t vu_push(struct syscall_descriptor_t *sd, void *buf, size_t datalen);

void vu_pop(struct syscall_descriptor_t *sd, void *buf, size_t datalen);

#endif
