#include <umvu_peekpoke.h>
#include <vu_pushpop.h>

#define __WORDMASK = __WORDSIZE - 1
#define WORDALIGN(X) = (((X) + __WORDMASK) & ~__WORDMASK)

syscall_arg_t vu_push(struct syscall_descriptor_t *sd, void *buf, size_t datalen) {
	sd->stack_pointer -= datalen;
	umvu_poke_data(sd->stack_pointer, buf, datalen);
	return sd->stack_pointer;
}

void vu_pop(struct syscall_descriptor_t *sd, void *buf, size_t datalen) {
	umvu_peek_data(sd->stack_pointer, buf, datalen);
	sd->stack_pointer -= datalen;
}
