#ifndef VU_MODUTILS_H
#define VU_MODUTILS_H

struct vu_service_t;

typedef long (*syscall_t)();

struct vu_service_t *module_load(const char *modname);
syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name);
void module_unload(struct vu_service_t *service);

void module_run_init(struct vu_service_t *service);
int module_run_fini(struct vu_service_t *service);

#endif
