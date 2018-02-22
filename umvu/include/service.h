#ifndef SERVICE_H
#define SERVICE_H

#include <vumodule.h>
#include <hashtable.h>

#define BINFMT_MODULE_ALLOC 1
#define BINFMT_KEEP_ARG0 2

struct vuht_entry_t;
typedef long (*syscall_t)();

struct binfmt_req_t {
	char *path;
	char *filehead;
	int fileheadsize;
	int fileheadlen;
	int flags;
};

struct vu_service_t {
	struct vu_module_t *mod;
	void *dlhandle;
	struct vuht_entry_t *service_ht;
	void *private;
	syscall_t module_syscall[];
};

/**A static thread variable is each time initialized with the module hash table element choosen by the hypervisor,
 so that the module can access this hte too.
 At the module load it is initialized with the first hte inserted (CHECKMODULE,modname,strlen(modname), service,...) */
void vu_mod_setht(struct vuht_entry_t *);
struct vuht_entry_t *vu_mod_getht(void);

/**Uniform way to call the module system call implementation.*/
__attribute__((always_inline))
	static inline syscall_t service_syscall(struct vuht_entry_t *ht, int vu_syscall_number) {
		struct vu_service_t *service = vuht_get_service(ht);
		vu_mod_setht(ht);
		return service->module_syscall[vu_syscall_number];
	}

#endif

