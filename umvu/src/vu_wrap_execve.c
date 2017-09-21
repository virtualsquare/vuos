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
#include <umvu_tracer.h>
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

#define BINFMTBUFLEN 128
static __thread char *tmp_path;

void copyfile(struct vuht_entry_t *ht, char *path, char *tmp_path) {
	int fdin, fdout, n;
	char *buf[BUFSIZ];
	void *private;
	fdout = r_open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (fdout < 0)
		return;
	fdin = service_syscall(ht, __VU_open)(path, O_RDONLY, 0, &private);
	if (fdin < 0)
	 goto close_fdout;	
	while ((n = service_syscall(ht, __VU_read)(fdin, buf, BUFSIZ, private)) > 0) {
		r_write(fdout, buf, n);
	}
	service_syscall(ht, __VU_close)(fdin, private);
close_fdout:
	r_close(fdout);
}

static void rewrite_execve_filename(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, char *path, struct vu_stat *statbuf) {
	/* counter/random suffix needed (or mmap/vnode mgmgt) */
	tmp_path = vu_tmpfilename(statbuf->st_dev, statbuf->st_ino, "_x");
	copyfile(ht, path, tmp_path);
	rewrite_syspath(sd, tmp_path);
}

static int read_exec_header(struct vuht_entry_t *ht, struct binfmt_req_t *req) {
	int ret_value;
	int fd;
	if (ht) {
		void *private;
		fd = service_syscall(ht, __VU_open)(req->path, O_RDONLY, 0, &private);
		if (fd < 0)
			return -errno;
		ret_value = service_syscall(ht, __VU_read)(fd, req->filehead, req->fileheadsize, private);
		service_syscall(ht, __VU_close)(fd, private);
	} else {
		fd = r_open(req->path, O_RDONLY);
		if (fd < 0)
			return -errno;
		ret_value = read(fd, req->filehead, req->fileheadsize);
		close(fd);
	}
	req->fileheadlen = ret_value;
	return ret_value;
}

static void check_binfmt_misc(struct binfmt_req_t *req) {
	struct vuht_entry_t *binfmt_ht;
	if ((binfmt_ht = vuht_pick(CHECKBINFMT, &req, NULL, 0)) != NULL)
		vuht_drop(binfmt_ht);
}

static int need_interpreter(struct binfmt_req_t *req) {
	/* this heuristics should catch ELF, COFF and a.out */
	if (req->fileheadlen <= 2 || req->filehead[0] < '\n' || req->filehead[0] == '\177')
		return 0;
	if (req->filehead[0] == '#' && req->filehead[1] == '!')
		return 1;
	req->fileheadlen = snprintf(req->filehead, req->fileheadsize, "#!\n");
	return 1; /* XXX unknown => script ?? */  
}

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
	//printk("++ interpreter_fill_args |%s|%s|\n", interpreter, extra_arg);
	
	return *extra_arg == '\0' ? 1 : 2;
}

struct argv_item {
	uintptr_t arg;
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
		new->arg = arg;
		new->next = NULL;
		(*argv_item_scan) = new;
		argv_item_scan = &(new->next);
		argv += sizeof(uintptr_t);
	}
	return ret_value;
}

static void copy_argv(uintptr_t *newargv, struct argv_list *oldargv) {
	struct argv_item *scan, *next;
	for (scan = oldargv->argv_head; scan != NULL; scan = next, newargv++) {
		*newargv = scan->arg;
		//char *tmp;
		//tmp = umvu_peekdup_path(scan->arg);
		//printk("+arg %s\n", tmp);
		//xfree(tmp);
		next = scan->next;
		free(scan);
	}
	*newargv = 0;
}

static void rewrite_execve_argv(struct syscall_descriptor_t *sd, int extra_argc, char *extra_argv[], int flags) {
	//printk("rewrite_execve_argv\n");
	struct argv_list argv_list = load_argv(sd);
	uintptr_t newargv[argv_list.argc + extra_argc + 1];
	newargv[0] = vu_push(sd, extra_argv[0], strlen(extra_argv[0]) + 1);
	//printk("argv[0] = %s\n", extra_argv[0]);
	if (extra_argc > 1) {
		newargv[1] = vu_push(sd, extra_argv[1], strlen(extra_argv[1]) + 1);
		//printk("argv[1] = %s\n", extra_argv[1]);
	}
	copy_argv(newargv + extra_argc, &argv_list);
	/* XXX */ newargv[extra_argc] = sd->syscall_args[0];
	sd->syscall_args[1] = vu_push(sd, newargv, sizeof(uintptr_t) * (argv_list.argc + extra_argc + 1));
}

void wi_execve(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		char exec_head[BINFMTBUFLEN];
		struct binfmt_req_t binfmt_req = {
			.path = sd->extra->path,
			.filehead = exec_head,
			.fileheadsize = sizeof(exec_head),
			.fileheadlen = 0,
			.flags = 0
		};
		int ret_value;
		//printk("execve %s %x ht=%p\n", sd->extra->path, sd->extra->statbuf.st_mode, ht);
		if (sd->extra->statbuf.st_mode == 0) {
			sd->ret_value = -ENOENT;
			sd->action = SKIP;
			return;
		}  
		if (ht)
			ret_value = service_syscall(ht,__VU_access)(sd->extra->path, X_OK, 0);
		else
			ret_value = r_access(sd->extra->path, X_OK);
		if (ret_value != 0) {
			sd->ret_value = -errno;
      sd->action = SKIP;
      return;
    }

		ret_value = read_exec_header(ht, &binfmt_req);
		if (ret_value < 0) {
			sd->ret_value = ret_value;
			sd->action = SKIP;
			return;
		}

		check_binfmt_misc(&binfmt_req);

		if (need_interpreter(&binfmt_req)) {
			char *extra_argv[2];
			int extra_argc;
			struct vu_stat statbuf;
			struct vuht_entry_t *interpreter_ht;
			epoch_t e = set_vepoch(sd->extra->epoch);
			/* parse header + check absolute path */
			if ((extra_argc = interpreter_fill_args(&binfmt_req, extra_argv)) < 0) {
				sd->ret_value = -errno;
				sd->action = SKIP;
				return;
			}
			extra_argv[0] = get_nested_path(AT_FDCWD, extra_argv[0], &statbuf, FOLLOWLINK);
			if (extra_argv[0] == NULL) {
				sd->ret_value = -errno;
        sd->action = SKIP;
        return;
      }
			if (statbuf.st_mode == 0) {
				sd->ret_value = -ENOENT;
				sd->action = SKIP;
				xfree(extra_argv[0]);
				return;
			}
			interpreter_ht = vuht_pick(CHECKPATH, extra_argv[0], &statbuf, SET_EPOCH);
			
			if (interpreter_ht)
				ret_value = service_syscall(interpreter_ht,__VU_access)(extra_argv[0], X_OK, 0);
			else
				ret_value = r_access(extra_argv[0], X_OK);
			if (ret_value != 0) {
				sd->ret_value = -errno;
				sd->action = SKIP;
				xfree(extra_argv[0]);
				return;
			}
			rewrite_execve_argv(sd, extra_argc, extra_argv, binfmt_req.flags);
			if (interpreter_ht) {
				rewrite_execve_filename(interpreter_ht, sd, extra_argv[0], &statbuf);
				vuht_drop(interpreter_ht);
				sd->action = DOIT_CB_AFTER;
			} else
				rewrite_syspath(sd, extra_argv[0]);
			set_vepoch(e);
			xfree(extra_argv[0]);
		} else {
			if (ht) 
				rewrite_execve_filename(ht, sd, sd->extra->path, &sd->extra->statbuf);
			sd->action = DOIT_CB_AFTER;
		}
	}
}

static void clean_tmp_path(void) {
	if (tmp_path != NULL) {
		r_unlink(tmp_path);
		free(tmp_path);
		tmp_path = NULL;
	}
}

void wo_execve(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	clean_tmp_path();
	sd->ret_value = sd->orig_ret_value;
}

static void *execve_tracer_upcall(inheritance_state_t state, void *arg) {
	if (state == INH_EXEC)
		clean_tmp_path();
	return NULL;
}

__attribute__((constructor))
	static void init(void) {
		umvu_inheritance_upcall_register(execve_tracer_upcall);
	}


