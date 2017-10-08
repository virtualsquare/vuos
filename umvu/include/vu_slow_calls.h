#ifndef VU_SLOW_CALLS_H
#define VU_SLOW_CALLS_H
#include <stdint.h>
struct vuht_entry_t;

int vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested);

pthread_t vu_slowcall_during(int epfd);

int vu_slowcall_out(int epfd, pthread_t slowtid, struct vuht_entry_t *ht, int fd, uint32_t events, int nested);
#endif
