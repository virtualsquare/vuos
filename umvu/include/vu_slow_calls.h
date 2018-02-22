#ifndef VU_SLOW_CALLS_H
#define VU_SLOW_CALLS_H
#include <stdint.h>
struct vuht_entry_t;
struct slowcall;

/**epoll interface is prefferred.*/
struct slowcall *vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested);
/**A way to test if a systemcall on a fd will be blocking.*/
int vu_slowcall_test(struct slowcall *sc);

/**Blocking syscall: the hypervisor can't be blocked,so a new process will perform the poll task on the correct file descriptor.*/
pid_t vu_slowcall_during(struct slowcall *sc);
void vu_slowcall_out(struct slowcall *sc, struct vuht_entry_t *ht, int fd, uint32_t events, int nested);
#endif
