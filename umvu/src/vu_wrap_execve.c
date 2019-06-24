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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <ctype.h>

#include <linux_32_64.h>
#include <canonicalize.h>
#include <vu_log.h>
#include <vu_tmpdir.h>
#include <vu_pushpop.h>
#include <r_table.h>
#include <umvu_peekpoke.h>
#include <vu_inheritance.h>
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
#include <vu_mod_inheritance.h>
#include <vu_fnode_copy.h>

/* management of execve */
/* struct binfmt_req_t is defined in include vumodule.h */

static __thread struct vu_fnode_t *tmp_fnode;

static void rewrite_execve_filename(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, char *path, struct vu_stat *statbuf) {
	char *tmp_path;
	tmp_fnode = vu_fnode_create(ht, path, statbuf, 0, -1, NULL);
	tmp_path = vu_fnode_get_vpath(tmp_fnode);
	vu_fnode_copyin(tmp_fnode);
	rewrite_syspath(sd, tmp_path);
}

/* read the header of the executable to test if an interpreter is required.
	 (e.g. using #! or binfmt_misc) */
static int read_exec_header(struct vuht_entry_t *ht, struct binfmt_req_t *req) {
	int ret_value;
	int fd;
	if (ht) {
		void *private;
		fd = service_syscall(ht, __VU_open)(vuht_path2mpath(ht, req->path), O_RDONLY, 0, &private);
		if (fd < 0)
			return -errno;
		ret_value = service_syscall(ht, __VU_read)(fd, req->filehead, BINFMTBUFLEN, private);
		service_syscall(ht, __VU_close)(fd, private);
	} else {
		fd = r_open(req->path, O_RDONLY);
		if (fd < 0)
			return -errno;
		ret_value = read(fd, req->filehead, BINFMTBUFLEN);
		close(fd);
	}
	req->fileheadlen = ret_value;
	return ret_value;
}

/* the confirm function re-assigns the filehead field of the struct binfmt_req to
 "!%" + path of the interpreter */
static void check_binfmt_misc(struct binfmt_req_t *req) {
	struct vuht_entry_t *binfmt_ht;
	if ((binfmt_ht = vuht_pick(CHECKBINFMT, req, NULL, 0)) != NULL)
		vuht_drop(binfmt_ht);
}

static int need_interpreter(struct binfmt_req_t *req) {
	/* this heuristics should catch ELF, COFF and a.out */
	if (req->fileheadlen <= 2 || req->filehead[0] < '\n' || req->filehead[0] == '\177')
		return 0;
	if (req->filehead[0] == '#' && req->filehead[1] == '!')
		return 1;
	req->fileheadlen = snprintf(req->filehead, BINFMTBUFLEN, "#!/bin/sh\n");
	return 1; /* XXX unknown => script ?? */
}

/* get args in the interpreter #! line */
int interpreter_fill_args(struct binfmt_req_t *req, char *argv[2]) {
	char *interpreter = req->filehead + 2;
	char *extra_arg;
	char *scan;
  char *term;
	if ((scan = memchr(req->filehead, '\n', req->fileheadlen)) != NULL)
    *scan = 0;
	if ((scan = memchr(req->filehead, '\0', req->fileheadlen)) == NULL ||
			req->filehead[0] != '#' || req->filehead[1] != '!') {
		errno = EINVAL;
    return -1;
	}
  interpreter += strspn(interpreter, " \t");
  scan = interpreter;
  scan += strcspn(scan, " \t\n");
  term = scan;
  scan += strspn(scan, " \t");
  extra_arg = scan;
  scan += strcspn(scan, "\n");
  *scan = 0;
  *term = 0;
	argv[0] = interpreter;
	argv[1] = extra_arg;
	
	return *extra_arg == '\0' ? 1 : 2;
}

struct argv_item {
	uintptr_t arg;
	char *larg;
	struct argv_item *next;
};

struct argv_list {
	int argc;
	struct argv_item *argv_head;
};

static struct argv_list load_argv(struct syscall_descriptor_t *sd) {
	struct argv_list ret_value = {
		.argc = 0,
		.argv_head = NULL
	};
	uintptr_t argv = sd->syscall_args[1];
	struct argv_item **argv_item_scan = &ret_value.argv_head;
	while (1) {
		uintptr_t arg;
		struct argv_item *new;
		umvu_peek_data(argv, &arg, sizeof(uintptr_t));
		if (arg == 0)
			break;
		ret_value.argc++;
		new = malloc(sizeof(struct argv_item));
		fatal(new);
		new->arg = arg;
		new->larg = NULL;
		new->next = NULL;
		(*argv_item_scan) = new;
		argv_item_scan = &(new->next);
		argv += sizeof(uintptr_t);
	}
	return ret_value;
}

static void argv_behead(struct argv_list *list) {
	if (list->argv_head != NULL) {
		struct argv_item *old = list->argv_head;
		list->argv_head = list->argv_head->next;
		xfree(old);
		list->argc -= 1;
	}
}

static void argv_addhead(struct argv_list *list, uintptr_t arg, char *larg) {
	struct argv_item *new;
	new = malloc(sizeof(struct argv_item));
	fatal(new);
	new->arg = arg;
	new->larg = larg;
	new->next = list->argv_head;
	list->argv_head = new;
	list->argc += 1;
}

static void copy_argv(uintptr_t *newargv, struct argv_list *argv) {
	struct argv_item *scan, *next;
	for (scan = argv->argv_head; scan != NULL; scan = next, newargv++) {
		*newargv = scan->arg;
		char *tmp;
		tmp = umvu_peekdup_path(scan->arg);
		xfree(tmp);
		next = scan->next;
		free(scan);
	}
	*newargv = 0;
}

static void push_argv(struct syscall_descriptor_t *sd, struct argv_list *argv) {
	struct argv_item *scan;
  for (scan = argv->argv_head; scan != NULL; scan = scan->next) {
		if (scan->arg == 0)
			scan->arg =  vu_push(sd, scan->larg, strlen(scan->larg) + 1);
	}
}

static void rewrite_execve_argv(struct syscall_descriptor_t *sd, struct argv_list *argv_list) {
	uintptr_t newargv[argv_list->argc + 1];
	push_argv(sd, argv_list);
	copy_argv(newargv, argv_list);
	sd->syscall_args[1] = vu_push(sd, newargv, sizeof(uintptr_t) * (argv_list->argc + 1));
}

static int existence_check(struct syscall_descriptor_t *sd, struct vu_stat *buf) {
	if (buf->st_mode == 0) {
		sd->ret_value = -ENOENT;
		sd->action = SKIPIT;
		return -1;
	} else
		return 0;
}

static int xok_check(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, char *path) {
	int ret_value;
	if (ht)
		ret_value = service_syscall(ht,__VU_access)(vuht_path2mpath(ht, path), X_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW);
	else
		ret_value = r_faccessat(AT_FDCWD, path, X_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW);
	if (ret_value != 0) {
		sd->ret_value = -errno;
		sd->action = SKIPIT;
		return -1;
	} else
		return 0;
}

/* stuid/setgid must be forwarded to vu_mod_inheritance.c.
	 uid/gid managing modules must be informed that the starting program is set[ug]id */
static void exec_setuid_setgid(struct vu_stat *statbuf) {
	if (statbuf->st_mode & S_ISUID)
		vu_exec_setuid(statbuf->st_uid);
	if (statbuf->st_mode & S_ISGID)
		vu_exec_setgid(statbuf->st_gid);
}

/* The interpreter itself may need an interpreter...
	 this function processes this recursion up to EXECVE_MAX_DEPTH levels */
#define EXECVE_MAX_DEPTH 4

static void recursive_interpreter(struct binfmt_req_t *req, struct syscall_descriptor_t *sd, struct argv_list *argv_list, int depth) {
	struct binfmt_req_t new_req = {
		.path = NULL,
		.fileheadlen = 0,
		.flags = 0
	};
	char *extra_argv[2];
	int extra_argc;
	struct vu_stat statbuf;
	struct vuht_entry_t *interpreter_ht;
	int ret_value;

	if (depth > EXECVE_MAX_DEPTH) {
		sd->ret_value = -ELOOP;
    sd->action = SKIPIT;
    return;
  }

	epoch_t e = set_vepoch(sd->extra->epoch);
	if ((extra_argc = interpreter_fill_args(req, extra_argv)) < 0) {
		sd->ret_value = -errno;
		sd->action = SKIPIT;
		return;
	}
	extra_argv[0] = get_path(AT_FDCWD, (syscall_arg_t) extra_argv[0], &statbuf, FOLLOWLINK, NULL, VU_NESTED);
	if (extra_argv[0] == NULL) {
		sd->ret_value = -errno;
		sd->action = SKIPIT;
		return;
	}
	if (existence_check(sd, &statbuf) < 0) {
		xfree(extra_argv[0]);
		return;
	}
	interpreter_ht = vuht_pick(CHECKPATH, extra_argv[0], &statbuf, SET_EPOCH);
	if (xok_check(interpreter_ht, sd, extra_argv[0]) < 0) {
		xfree(extra_argv[0]);
		if (interpreter_ht)
			vuht_drop(interpreter_ht);
		return;
	}

	if (!(req->flags & BINFMT_PRESERVE_ARGV0))
		argv_behead(argv_list);

	if (depth == 1)
		argv_addhead(argv_list, sd->syscall_args[0], NULL);
	else
		argv_addhead(argv_list, 0, req->path);

	if (extra_argc > 1)
		argv_addhead(argv_list, 0, extra_argv[1]);

	argv_addhead(argv_list, 0, extra_argv[0]);

	new_req.path = extra_argv[0];
	ret_value = read_exec_header(interpreter_ht, &new_req);
	if (ret_value < 0) {
		sd->ret_value = ret_value;
		sd->action = SKIPIT;
		xfree(extra_argv[0]);
		if (interpreter_ht)
			vuht_drop(interpreter_ht);
		return;
	}

	check_binfmt_misc(&new_req);

	if (need_interpreter(&new_req)) {
		recursive_interpreter(&new_req, sd, argv_list, depth + 1);
	} else {
		exec_setuid_setgid(&statbuf);
		rewrite_execve_argv(sd, argv_list);
		if (interpreter_ht) {
			rewrite_execve_filename(interpreter_ht, sd, extra_argv[0], &statbuf);
			sd->action = DOIT_CB_AFTER;
		} else
			rewrite_syspath(sd, extra_argv[0]);
	}
	set_vepoch(e);
	xfree(extra_argv[0]);
	if (interpreter_ht)
		vuht_drop(interpreter_ht);
}

/* Wrapin for execve */
void wi_execve(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		struct binfmt_req_t binfmt_req = {
			.path = sd->extra->path,
			.fileheadlen = 0,
			.flags = 0
		};
		int ret_value;
		//printk("execve %s %x ht=%p\n", sd->extra->path, sd->extra->statbuf.st_mode, ht);
		if (existence_check(sd, &sd->extra->statbuf) < 0)
			return;

		if (xok_check(ht, sd, sd->extra->path) < 0)
			return;

		ret_value = read_exec_header(ht, &binfmt_req);
		if (ret_value < 0) {
			sd->ret_value = ret_value;
			sd->action = SKIPIT;
			return;
		}

		check_binfmt_misc(&binfmt_req);

		if (need_interpreter(&binfmt_req)) {
			struct argv_list argv_list = load_argv(sd);

			recursive_interpreter(&binfmt_req, sd, &argv_list, 1);
		} else {
			exec_setuid_setgid(&sd->extra->statbuf);
			if (ht) {
				rewrite_execve_filename(ht, sd, sd->extra->path, &sd->extra->statbuf);
				sd->action = DOIT_CB_AFTER;
			}
		}
	}
}

/* use inheritance to clean the temporary node */

static void clean_tmp_fnode(void) {
	if (tmp_fnode != NULL) {
		vu_fnode_close(tmp_fnode);
		tmp_fnode = NULL;
	}
}

/* if execve causes the "output" filter to run (after the syscall) it means
	 that execve failed */

void wo_execve(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	clean_tmp_fnode();
	sd->ret_value = sd->orig_ret_value;
}

static void *execve_tracer_upcall(inheritance_state_t state, void *arg) {
	if (state == INH_EXEC)
		clean_tmp_fnode();
	return NULL;
}

__attribute__((constructor))
	static void init(void) {
		vu_inheritance_upcall_register(execve_tracer_upcall);
	}


