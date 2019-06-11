#ifndef VU_INITFINI_H
#define VU_INITFINI_H

/* hypervisor constructors/destructors.
	 vu_init calls all the upcalls registered by vu_constructor_register.
	 vu_fini calls all the upcalls registered by vu_destructor_register.

	 umvu_main calls vu_init just before starting the tracer and vu_fini
	 as soon as the tracer terminates */

typedef void (*voidfun_t)(void);

void vu_constructor_register(voidfun_t upcall);
void vu_destructor_register(voidfun_t upcall);

void vu_init(void);
void vu_fini(void);

#endif
