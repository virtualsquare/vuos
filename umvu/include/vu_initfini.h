#ifndef VU_INITFINI_H
#define VU_INITFINI_H

/* hypervisor constructors/destructors.
	 vu_init calls all the upcalls registered by vu_constructor_register.
	 vu_fini calls all the upcalls registered by vu_destructor_register.

	 umvu_main calls vu_init just before starting the tracer and vu_fini
	 as soon as the tracer terminates.

Warning: these functions are *NOT* thread safe. They have been designed
for __attribute__((constructor)) functions (so the call happens before
going multi-threading)

 */

typedef void (*voidfun_t)(void);

/* register a constructor/destructor */
void vu_constructor_register(voidfun_t upcall);
void vu_destructor_register(voidfun_t upcall);

/* this functions are for main: start all the constructors (init),
	 and run all the destructors (fini) */
void vu_init(void);
void vu_fini(void);

#endif
