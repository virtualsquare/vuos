#ifndef VU_SLOW_CALLS_H
#define VU_SLOW_CALLS_H

/* management of slow syscalls: those who may block. */

#include <stdint.h>
struct vuht_entry_t;
struct slowcall;

/* This syscall requires 'events' to run, use this in the IN wrapper */
struct slowcall *vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested);

/* suspend until the slowcall can succeed. the return value must be assigned to sd->waiting_pid */
/* this function is for the DURING wrapper */
pid_t vu_slowcall_during(struct slowcall *sc);

/* this function is forthe OUT wrapper.
	 undo what vu_slowcall_in did and free the struct slowcall */
void vu_slowcall_out(struct slowcall *sc, struct vuht_entry_t *ht, int fd, uint32_t events, int nested);

/* test if the syscall can run (it is an optimization)*/
int vu_slowcall_test(struct slowcall *sc);
#endif
