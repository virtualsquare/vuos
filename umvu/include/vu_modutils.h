#ifndef VU_MODUTILS_H
#define VU_MODUTILS_H

/* loading/unloading of modules */
/* vu_syscall_handler_pointer is used in vumodule.h
	 by "vu_syscall_handler" macro */

typedef void (* voidfun)(void);

struct vu_service_t;

#if __STDC_VERSION__ >= 202000L
typedef long (*syscall_t)(...);
#else
typedef long (*syscall_t)();
#endif

struct vu_service_t *module_load(const char *modname);
syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name);
void module_unload(struct vu_service_t *service);

voidfun *module_getsym(struct vu_service_t *service, char *symbol);
void module_run_init(struct vu_service_t *service);
int module_run_fini(struct vu_service_t *service);

#endif
