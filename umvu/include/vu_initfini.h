#ifndef VU_INITFINI_H
#define VU_INITFINI_H

typedef void (*voidfun_t)(void);

/** Allows some files to register their constructor/descructor functions. */
void vu_constructor_register(voidfun_t upcall);
void vu_destructor_register(voidfun_t upcall);

/**Running files constructor/desctructor functions.*/
void vu_init(void);
void vu_fini(void);

#endif
