#ifndef SERVICE_H
#define SERVICE_H

#include <vumodule.h>
#include <hashtable.h>

struct vuht_entry_t;
typedef long (*syscall_t)();

struct vu_service_t {
	struct vu_module_t *mod;
	void *dlhandle;
	struct vuht_entry_t *service_ht;
	void *private;
	syscall_t module_syscall[];
};

struct vuht_entry_t *vu_mod_getht(void);
void vu_mod_setht(struct vuht_entry_t *ht);

__attribute__((always_inline))
	static inline syscall_t service_syscall(struct vuht_entry_t *ht, int vu_syscall_number) {
		struct vu_service_t *service = vuht_get_service(ht);
		return service->module_syscall[vu_syscall_number];
	}

#endif

