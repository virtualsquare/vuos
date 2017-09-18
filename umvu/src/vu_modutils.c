#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <service.h>
#include <pthread.h>
#include <xcommon.h>
#include <vu_log.h>
#include <syscall_defs.h>
#include <syscall_table.h>

/* this is convenient since casting the return value of dlsym() to
 * a function pointer erroneously procudes a warning */
#pragma GCC diagnostic ignored "-Wpedantic"

/* XXX temporary */
#define MODULES_DIR "/usr/local/lib/vu/modules"

long sys_enosys(void) {
	errno = ENOSYS;
	return -1;
}

/* This will be prefixed with getent("$HOME") */
#define USER_MODULES_DIR "/.vu/modules"
#define MODULES_EXT ".so"

#ifndef MAX
#define MAX(a, b) ((a > b) ? a : b)
#endif

static inline char *gethomedir(void) {
	char *homedir = getenv("HOME");
	/* If there is no home directory, use CWD */
	if (!homedir)
		homedir = ".";
	return homedir;
}

/*
 * Try to dlopen a module (o submodule) trying different names and locations:
 *
 * 1) dlopen(modname)
 * 2) dlopen(modname.so)
 * 3) dlopen(user_vu_plugin_directory/modname)
 * 4) dlopen(user_vu_plugin_directory/modname.so)
 * 5) dlopen(global_vu_plugin_directory/modname)
 * 6) dlopen(global_vu_plugin_directory/modname.so)
 *
 */

static void *module_dlopen(const char *modname, int flags)
{
#define TRY_DLOPEN(...) \
{ \
	snprintf(testpath, tplen, __VA_ARGS__); \
	if ((handle = dlopen(testpath, flags))) { \
		return handle; \
	} \
}
	void *handle;
	char *homedir = gethomedir();
	int tplen = strlen(modname) + strlen(MODULES_EXT) +
		2 + // + 1 is for a '/' and + 1 for \0
		MAX(strlen(MODULES_DIR),
				strlen(homedir) + strlen(USER_MODULES_DIR));
	char testpath[tplen];

	if (!modname)
		return NULL;
	if ((handle = dlopen(modname, flags)))
		return handle;

	TRY_DLOPEN("%s%s", modname, MODULES_EXT);
	TRY_DLOPEN("%s%s/%s", homedir, USER_MODULES_DIR, modname);
	TRY_DLOPEN("%s%s/%s%s", homedir, USER_MODULES_DIR, modname, MODULES_EXT);
	TRY_DLOPEN("%s/%s", MODULES_DIR, modname);
	TRY_DLOPEN("%s/%s%s", MODULES_DIR, modname, MODULES_EXT);
	return NULL;
#undef TRY_DLOPEN
}

struct vu_service_t *module_load(const char *modname)
{
	void *handle;
	struct vu_module_t *module;

	if (!(handle = module_dlopen(modname, RTLD_LAZY | RTLD_GLOBAL))) {
		errno = ENOENT;
		return NULL;
	}

	/* populate umview_service_t structure */
	if ((module = dlsym(handle, "vu_module"))) {
		struct vu_service_t *service = malloc(sizeof(struct vu_service_t) +
				VU_NR_SYSCALLS * sizeof(syscall_t));
		int prefixlen = strlen(module->name) + 4;
		int fnamelen = prefixlen + VU_SYSCALL_MAX_NAMELEN + 1;
		char fname[fnamelen];
		int i;
		fatal(service);
		printkdebug(m, "Loading %s", module->name);
		service->mod = module;
		service->dlhandle = handle;
		service->service_ht = NULL;
		service->private = NULL;
		snprintf(fname, fnamelen, "vu_%s_",module->name);
		for (i = 0; i < VU_NR_MODULE_SYSCALLS; i++) {
			strcpy(fname+prefixlen, vu_syscall_names[i]);
			service->module_syscall[i] = dlsym(handle, fname);
			if (service->module_syscall[i] == NULL) {
				service->module_syscall[i] = sys_enosys;
			} else {
				printkdebug(m, "%s syscall %s -> %s", module->name, vu_syscall_names[i], fname);
			}
		}
		return service;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name) {
	int i;
	static syscall_t useless;
	for (i = 0; i < VU_NR_MODULE_SYSCALLS; i++) {
		if (strcmp(name, vu_syscall_names[i]) == 0) 
			return &service->module_syscall[i];
	}
  useless	= NULL;
	return &useless;
}

void module_unload(struct vu_service_t *service)
{
	printkdebug(m, "Unloading %s", service->mod->name);
	fatal(service);
	xfree(service);
	dlclose(service->dlhandle);
}

void module_run_init(struct vu_service_t *service) {
	int initnamelen = strlen(service->mod->name) + 4 + 5;
	char initname[initnamelen];
	void * (*init)(void);
	snprintf(initname, initnamelen, "vu_%s_init",service->mod->name);
	init = dlsym(service->dlhandle, initname);
	if (init) {
		printkdebug(m, "%s running init %s", service->mod->name, initname);
		service->private = init();
	}
}

void module_run_fini(struct vu_service_t *service) {
	  int fininamelen = strlen(service->mod->name) + 4 + 5;
  char fininame[fininamelen];
  void (*fini)(void *);
  snprintf(fininame, fininamelen, "vu_%s_fini",service->mod->name);
  fini = dlsym(service->dlhandle, fininame);
  if (fini) {
		printkdebug(m, "%s running fini %s", service->mod->name, fininame);
		fini(service->private);
	}
}

__attribute__((constructor))
  static void init(void) {
    debug_set_name(m, "MODULE");
  }


