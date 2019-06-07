#ifndef SERVICE_H
#define SERVICE_H

#include <vumodule.h>
#include <hashtable.h>

/* each module define a service.
	 services are registered in the hashtable (he key is the module name */

struct vuht_entry_t;
typedef long (*syscall_t)();

struct vu_service_t {
	// pointer to a static structure named "vu_module" defined in the module
	// this structure defines the name and a short description of the module
	// the presence of such a structure is used as a test (that the module
	// has been designed for vuos.
	struct vu_module_t *mod;
	// modules are loaded as dynamic library plug-ins.
	// this is the handle returned by dl_open
	void *dlhandle;
	// the hash table pointer of the service itself
	struct vuht_entry_t *service_ht;
	// private data of the module (modules can use this pointer as they please.
	void *private;
	// table of vu_syscalls implementation.
	syscall_t module_syscall[];
};

struct vuht_entry_t *vu_mod_getht(void);
void vu_mod_setht(struct vuht_entry_t *ht);

/* inline function: it is here for performance.
	 it returns the pointer of the suscall implementation....
	 an example of this inline usage is:
	 retval = service_syscall(ht, __VU_read)(fd, buf, buflen);
 */
__attribute__((always_inline))
	static inline syscall_t service_syscall(struct vuht_entry_t *ht, int vu_syscall_number) {
		struct vu_service_t *service = vuht_get_service(ht);
		return service->module_syscall[vu_syscall_number];
	}

#endif

