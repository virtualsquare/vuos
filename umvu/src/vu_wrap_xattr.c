#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>

#include <linux_32_64.h>
#include <vu_log.h>
#include <r_table.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <path_utils.h>
#include <vu_fs.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <vu_wrapper_utils.h>

void wi_lgetxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		uintptr_t valueaddr = sd->syscall_args[2];
		size_t size = sd->syscall_args[3];
		char *name;
		char *value = NULL;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fgetxattr: 
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		if (valueaddr > 0) vu_alloc_arg(valueaddr, value, size, nested);
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_lgetxattr)(sd->extra->path, name, value, size, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else {
			sd->ret_value = ret_value;
			if (ret_value > 0 && valueaddr > 0)
				vu_poke_arg(valueaddr, value, ret_value, nested);
		}
		vu_free_arg(value, nested);
	}
}

void wi_lsetxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		uintptr_t valueaddr = sd->syscall_args[2];
		size_t size = sd->syscall_args[3];
		int flags = sd->syscall_args[4];
		char *name;
		char *value;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fsetxattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		vu_peek_alloc_arg(valueaddr, value, size, nested);
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_lsetxattr)(sd->extra->path, name, value, size, flags, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else 
			sd->ret_value = ret_value;
		vu_free_arg(value, nested);
	}
}

void wi_llistxattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t listaddr = sd->syscall_args[1];
		size_t size = sd->syscall_args[2];
		char *list = NULL;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_flistxattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		if (listaddr > 0) vu_alloc_arg(listaddr, list, size, nested);
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_llistxattr)(sd->extra->path, list, size, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else {
			sd->ret_value = ret_value;
			if (ret_value > 0 && listaddr > 0)
				vu_poke_arg(listaddr, list, ret_value, nested);
		}
		vu_free_arg(list, nested);
	}
}

void wi_lremovexattr(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int ret_value;
		int syscall_number = sd->syscall_number;
		/* args */
		uintptr_t nameaddr = sd->syscall_args[1];
		char *name;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_fremovexattr:
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
		}
		vu_alloc_peek_local_strarg(nameaddr, name, PATH_MAX, nested);
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_lremovexattr)(sd->extra->path, name, sfd, private);
		if (ret_value < 0)
			sd->ret_value = (errno == ENOSYS) ? -ENOTSUP : -errno;
		else 
			sd->ret_value = ret_value;
	}
}
