#include <string.h>
#include <limits.h>
#include <hashtable.h>
#include <umvu_peekpoke.h>
#include <vu_execute.h>
#include <vu_fd_table.h>
#include <arch_table.h>
#include <vu_log.h>
#include <epoch.h>

struct vuht_entry_t *choice_path(struct syscall_descriptor_t *sd) {
	struct syscall_extra_t *extra = sd->extra;
	int nested = extra->nested;
	struct vuht_entry_t *ht;
	if (extra->path == NULL) {
		if (extra->path_errno != 0) {
			sd->ret_value = -extra->path_errno;
			sd->action = SKIP;
		}
		ht = NULL;
	} else
		ht = vuht_pick(CHECKPATH, extra->path, &extra->statbuf, SET_EPOCH);
	printkdebug(c, "path %s: %c ht %p err = %d %s", extra->path, 
			nested ? 'N' : '-', ht,
			(sd->action == SKIP) ? -sd->ret_value : 0,
			(sd->action == SKIP) ? "SKIP" : "");
	return ht;
}

struct vuht_entry_t *choice_fd(struct syscall_descriptor_t *sd) {
	struct syscall_extra_t *extra = sd->extra;
	int fd = sd->syscall_args[0];
	int nested = extra->nested;
	struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
	char path[PATH_MAX];
	vu_fd_get_path(fd, nested, path, PATH_MAX);
	extra->path = strdup(path);
	extra->statbuf.st_mode = vu_fd_get_mode(fd, nested);
	printkdebug(c, "fd %d %s: %c ht %p", fd, extra->path, 
			nested ? 'N' : '-', ht);
	if (ht) 
		vuht_pick_again(ht);
	return ht;
}

struct vuht_entry_t *choice_std(struct syscall_descriptor_t *sd) {
	int syscall_number = sd->syscall_number;
	int patharg = vu_arch_table_patharg(syscall_number);
	if (patharg >= 0)
		return choice_path(sd);
	else
		return choice_fd(sd);
}

struct vuht_entry_t *choice_std_nonest(struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (nested)
		return NULL;
	else
		return choice_std(sd);
}


struct vuht_entry_t *choice_utimensat(struct syscall_descriptor_t *sd) {
	int syscall_number = sd->syscall_number;
	switch (syscall_number) {
		case __NR_utimensat: {
													 syscall_arg_t pathaddr = sd->syscall_args[1];
													 if (pathaddr == (syscall_arg_t) NULL)
														 return choice_fd(sd);
													 else
														 return choice_path(sd);

												 }
		default:
												 return choice_path(sd);

	}
}

struct vuht_entry_t *choice_mount(struct syscall_descriptor_t *sd) {
  int nested = sd->extra->nested;
	if (nested)
		return NULL;
	else {
		struct syscall_extra_t *extra = sd->extra;
		struct vuht_entry_t *ht;
		char filesystemtype[PATH_MAX];
		syscall_arg_t filesystemtype_addr = sd->syscall_args[2];
		umvu_peek_str(filesystemtype_addr, filesystemtype, PATH_MAX);
		ht = vuht_pick(CHECKFSTYPE, filesystemtype, NULL, SET_EPOCH);
		printkdebug(c, "mount %s on %s: - ht %p", filesystemtype, extra->path, ht);
    return ht;
	}
}

struct vuht_entry_t *choice_umount2(struct syscall_descriptor_t *sd) {
  int nested = sd->extra->nested;
	if (nested)
		return NULL;
	else {
		struct syscall_extra_t *extra = sd->extra;
		struct vuht_entry_t *ht;
		if (extra->path == NULL) {
			if (extra->path_errno != 0) {
				sd->ret_value = -extra->path_errno;
				sd->action = SKIP;
			}
			ht = NULL;
		} else
			ht = vuht_pick(CHECKPATHEXACT, extra->path, &extra->statbuf, SET_EPOCH);
		printkdebug(c, "umount2 %s: - ht %p err = %d %s", extra->path, ht,
      (sd->action == SKIP) ? -sd->ret_value : 0,
      (sd->action == SKIP) ? "SKIP" : "");
		return ht;
	}
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(c, "CHOICE");
	}

