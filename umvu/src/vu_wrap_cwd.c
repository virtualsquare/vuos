#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>

#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <linux_32_64.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <vu_tmpdir.h>
#include <vu_fs.h>
#include <path_utils.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>

/* chdir, fchdir */
void wi_chdir(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		int mode = sd->extra->statbuf.st_mode;
		if (S_ISDIR(mode)) {
			/* change the call to "chdir(fakedir)" */
			sd->syscall_number = __NR_chdir;
			if (ht)
				rewrite_syspath(sd, "/"); /* this directory should always exist */
			else
				rewrite_syspath(sd, sd->extra->path); 
			sd->action = DOIT_CB_AFTER;
		} else {
			if (mode == 0)
				sd->ret_value = -ENOENT;
			else if (sd->extra->path_errno != 0)
				sd->ret_value = -sd->extra->path_errno;
			else
				sd->ret_value = -ENOTDIR;
			sd->action = SKIP;
		}
	}
}

void wo_chdir(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int ret_value = sd->orig_ret_value;

	if (ret_value >= 0)
		vu_fs_set_cwd(sd->extra->path);
	sd->ret_value = sd->orig_ret_value;
}

/* getcwd */
void wi_getcwd(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		syscall_arg_t bufaddr = sd->syscall_args[0];
		syscall_arg_t bufsize = sd->syscall_args[0];
		char plaincwd[PATH_MAX];
		char root[PATH_MAX];
		char *cwd = plaincwd;
		size_t rootlen;
		size_t cwdlen;
		vu_fs_get_cwd(plaincwd, PATH_MAX);
		vu_fs_get_rootdir(root, PATH_MAX);
		rootlen = strlen(root);
		if (root[1] == 0) 
			root[0] = 0;
		if (strncmp(plaincwd, root, rootlen) == 0)
			cwd += rootlen;
		cwdlen = strlen(cwd)+1;
		if (cwdlen < bufsize)
			bufsize = cwdlen;
		umvu_poke_data(bufaddr, cwd, bufsize);
		sd->ret_value = cwdlen;
		sd->action = SKIP;
	}
}
