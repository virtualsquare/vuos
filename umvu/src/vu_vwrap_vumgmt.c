#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <xcommon.h>
#include <umvu_peekpoke.h>
#include <vu_name.h>
#include <hashtable.h>
#include <syscall_table.h>
#include <syscall_defs.h>
#include <service.h>
#include <vu_log.h>
#include <path_utils.h>
#include <vu_modutils.h>
#include <r_table.h>
#define _VU_HYPERVISOR
#include <vulib.h>  // to check consistecy with user libraries

void vw_insmod(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct vuht_entry_t *sht;
	struct vu_service_t *service;
	char name[PATH_MAX];
	char *modname;
	int permanent = (int)sd->syscall_args[1];
	if (umvu_peek_str(sd->syscall_args[0], name, PATH_MAX) < 0) {
		sd->ret_value = -EINVAL;
		return;
	}
	service = module_load(name);

	if (service == NULL) {
		int save_errno = errno;
		printk(KERN_ERR "loading of module %s failed: %s\n", name, strerror(save_errno));
		sd->ret_value = -errno;
		return;
	}

	modname = service->mod->name;

	if (vuht_check(CHECKMODULE, modname, NULL, 0)) {
		printk(KERN_ERR "module %s already loaded\n", modname);
		module_unload(service);
		sd->ret_value = -EEXIST;
		return;
	}

	sht = vuht_add(CHECKMODULE, modname, strlen(modname), service,
			NULL, NULL);

	service->ht = sht;
	service->mod->service = service;

	if (permanent)
		vuht_count_plus1(sht);

	module_run_init(service);
	sd->ret_value = 0;
}

void vw_rmmod(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	char name[PATH_MAX];
	struct vuht_entry_t *sht;
	struct vu_service_t *service;
	if (umvu_peek_str(sd->syscall_args[0], name, PATH_MAX) < 0) {
		sd->ret_value = -EINVAL;
		return;
	}
	sht = vuht_check(CHECKMODULE, name, NULL, 0);
	if (sht == NULL) {
		printk(KERN_ERR "module %s is not loaded\n", name);
		sd->ret_value = -ENOENT;
		return;
	} 
	service = vuht_get_service(sht);
	fatal(service);

	if (vuht_get_count(sht) != 0) {
		printk(KERN_ERR "module %s is already in use\n", name);
		sd->ret_value = -EADDRINUSE;
		return;
	}

	module_run_fini(service);
	service->mod->service = NULL;
	vuht_del(sht);
	module_unload(service);
	update_vepoch();
	sd->ret_value = 0;
}

static void list_item(struct vuht_entry_t *hte, void *arg)
{
	FILE *f = arg;
	struct vu_service_t *s = vuht_get_service(hte);
	struct vu_module_t *m = s->mod;
	fprintf(f, "%s: %s\n", m->name, m->description);
}

void vw_lsmod(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	syscall_arg_t buf_addr = sd->syscall_args[0];
	unsigned int buf_size = (unsigned int)sd->syscall_args[1];

	char *localbuf;
	size_t localbufsize;

	FILE *f = open_memstream(&localbuf, &localbufsize);
	forall_vuht_do(CHECKMODULE, list_item, f);
	fclose(f);
	localbufsize++; /* for the string terminator */

	if (buf_addr != 0) { /*NULL*/
		if (localbufsize < buf_size) 
			buf_size = localbufsize;
		umvu_poke_data(buf_addr, localbuf, buf_size);
	}
	xfree(localbuf);
	sd->ret_value = localbufsize;
}

void vuctl_getinfo(struct syscall_descriptor_t *sd) {
	syscall_arg_t info_addr  = sd->syscall_args[1];
	if (info_addr != 0) {
		struct vu_info info;
		memset(&info, 0, sizeof(info));
		r_uname(&info.uname);
		snprintf(&info.vu_serverid, sizeof(info.vu_serverid), "%d", getpid());
		get_vu_name(&info.vu_name, sizeof(info.vu_name));
		if (umvu_poke_data(info_addr, &info, sizeof(info)) < 0) 
			sd->ret_value = -EINVAL;
		else
			sd->ret_value = 0;
	} else
		sd->ret_value = 0;
}

void vuctl_setname(struct syscall_descriptor_t *sd) {
	char *vu_name[_UTSNAME_LENGTH+1];
	syscall_arg_t name_addr = sd->syscall_args[1];
	if (umvu_peek_str(name_addr, vu_name, _UTSNAME_LENGTH+1) < 0) {
    sd->ret_value = -EINVAL;
    return;
  }
	set_vu_name(vu_name);
	sd->ret_value = 0;
}

void vuctl_get_debugtags(struct syscall_descriptor_t *sd) {
	syscall_arg_t tags_addr = sd->syscall_args[1];
	syscall_arg_t len = sd->syscall_args[2];
	char tags[DEBUG_NTAGS+1];
	if (len > DEBUG_NTAGS+1)
		len = DEBUG_NTAGS+1;
	debug_get_tags(tags, len);
	if (umvu_poke_data(tags_addr, tags, strlen(tags) + 1) < 0)
		sd->ret_value = -EINVAL;
	else
		sd->ret_value = 0;
}

void vuctl_add_debugtags(struct syscall_descriptor_t *sd) {
	char tags[DEBUG_NTAGS+1];
	syscall_arg_t tags_addr = sd->syscall_args[1];
	if (umvu_peek_str(tags_addr, tags, DEBUG_NTAGS+1) < 0) {
    sd->ret_value = -EINVAL;
    return;
  }
	debug_add_tags(tags);
	sd->ret_value = 0;
}

void vuctl_del_debugtags(struct syscall_descriptor_t *sd) {
	char tags[DEBUG_NTAGS+1];
	syscall_arg_t tags_addr = sd->syscall_args[1];
	if (umvu_peek_str(tags_addr, tags, DEBUG_NTAGS+1) < 0) {
		sd->ret_value = -EINVAL;
		return;
	}
	debug_del_tags(tags);
	sd->ret_value = 0;
}

void vuctl_get_debugtagname(struct syscall_descriptor_t *sd) {
	syscall_arg_t tag = sd->syscall_args[1];
	syscall_arg_t buf_addr = sd->syscall_args[2];
	syscall_arg_t len = sd->syscall_args[3];
	if (len > PATH_MAX)
		len = PATH_MAX;
	char buf[len];
	debug_get_name(tag, buf, len);
	if (umvu_poke_data(buf_addr, buf, strlen(buf) + 1) < 0)
		sd->ret_value = -EINVAL;
	else
		sd->ret_value = 0;
}

void vuctl_setdebugcolors(struct syscall_descriptor_t *sd) {
	char colors[PATH_MAX];
	syscall_arg_t colors_addr = sd->syscall_args[1];
	if (umvu_peek_str(colors_addr, colors, PATH_MAX) < 0) {
		sd->ret_value = -EINVAL;
		return;
	}
	debug_set_color_string(colors);
	sd->ret_value = -EINVAL;
}

void vw_vuctl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	syscall_arg_t tag = sd->syscall_args[0];
	switch (tag) {
		case VUCTL_GETINFO:
			vuctl_getinfo(sd);
			break;
		case VUCTL_SETNAME:
			vuctl_setname(sd);
			break;
		case VUCTL_GET_DEBUGTAGS:
			vuctl_get_debugtags(sd);
			break;
		case VUCTL_ADD_DEBUGTAGS:
			vuctl_add_debugtags(sd);
			break;
		case VUCTL_DEL_DEBUGTAGS:
			vuctl_del_debugtags(sd);
			break;
		case VUCTL_GET_DEBUGTAGNAME:
			vuctl_get_debugtagname(sd);
			break;
		case VUCTL_SET_DEBUGCOLOR:
			vuctl_setdebugcolors(sd);
			break;
		default:
			sd->ret_value = -EINVAL;
	}
}
