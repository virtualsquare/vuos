#ifndef SERVICE_H
#define SERVICE_H

#include <vumodule.h>

#define BINFMT_MODULE_ALLOC 1
#define BINFMT_KEEP_ARG0 2

struct hashtable_obj_t;
typedef long (*syscall_t)();

struct binfmt_req_t {
	char *path;
	char *interp;
	char *extraarg;
	char *buf;
	int flags;
};

struct vu_service_t {
	struct vu_module_t *mod;
	void *dlhandle;
	struct hashtable_obj_t *ht;
	void *private;
	syscall_t module_syscall[];
};

#endif

