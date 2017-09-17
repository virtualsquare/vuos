#ifndef VU_INITFINI_H
#define VU_INITFINI_H

typedef void (*voidfun_t)(void);

void vu_constructor_register(voidfun_t upcall);
void vu_destructor_register(voidfun_t upcall);

void vu_init(void);
void vu_fini(void);

#endif
