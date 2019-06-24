/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <service.h>
#include <pthread.h>
#include <config.h>
#include <xcommon.h>
#include <vu_log.h>
#include <syscall_defs.h>
#include <syscall_table.h>

typedef void (* voidfun)(void);


long sys_enosys(void) {
	errno = ENOSYS;
	return -1;
}

/* This will be prefixed with getent("$HOME") */
#define USER_MODULES_PATH "/.vu/modules"
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
		MAX(strlen(MODULES_INSTALL_PATH),
				strlen(homedir) + strlen(USER_MODULES_PATH));
	char testpath[tplen];

	if (!modname)
		return NULL;
	if ((handle = dlopen(modname, flags)))
		return handle;

	TRY_DLOPEN("%s%s", modname, MODULES_EXT);
	TRY_DLOPEN("%s%s/%s", homedir, USER_MODULES_PATH, modname);
	TRY_DLOPEN("%s%s/%s%s", homedir, USER_MODULES_PATH, modname, MODULES_EXT);
	TRY_DLOPEN("%s/%s", MODULES_INSTALL_PATH, modname);
	TRY_DLOPEN("%s/%s%s", MODULES_INSTALL_PATH, modname, MODULES_EXT);
	return NULL;
#undef TRY_DLOPEN
}

/* utility function to load sub-modules.
	 currently it is a forwarding function to module_dlopen.
	 it has been defined as a specific function to permit
	 customization in the future. */
void *vu_mod_dlopen(const char *modname, int flags) {
	return module_dlopen(modname, flags);
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	if ((module = dlsym(handle, "vu_module"))) {
#pragma GCC diagnostic pop
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
			service->module_syscall[i] = dlsym(handle, fname);
#pragma GCC diagnostic pop
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

voidfun *module_getsym(struct vu_service_t *service, char *symbol) {
	char symnamelen = strlen(service->mod->name) + strlen(symbol) + 5;
	char symname[symnamelen];
	snprintf(symname, symnamelen, "vu_%s_%s",service->mod->name, symbol);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	return dlsym(service->dlhandle, symname);
#pragma GCC diagnostic pop
}

void module_run_init(struct vu_service_t *service) {
	void * (*init)(void);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	init = module_getsym(service, "init");
#pragma GCC diagnostic pop
	if (init) {
		printkdebug(m, "%s running vu_%s_init", service->mod->name, service->mod->name);
		service->private = init();
	}
}

int module_run_fini(struct vu_service_t *service) {
  int (*fini)(void *);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  fini = module_getsym(service, "fini");
#pragma GCC diagnostic pop
  if (fini) {
		printkdebug(m, "%s running vu_%s_fini", service->mod->name, service->mod->name);
		return fini(service->private);
	} else
		return 0;
}

__attribute__((constructor))
  static void init(void) {
    debug_set_name(m, "MODULE");
  }


