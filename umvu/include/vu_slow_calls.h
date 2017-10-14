#ifndef VU_SLOW_CALLS_H
#define VU_SLOW_CALLS_H
#include <stdint.h>
struct vuht_entry_t;
struct slowcall;

struct slowcall *vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested);
pid_t vu_slowcall_during(struct slowcall *sc);
void vu_slowcall_out(struct slowcall *sc, struct vuht_entry_t *ht, int fd, uint32_t events, int nested);
#endif
