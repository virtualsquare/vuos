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
			sd->action = SKIPIT;
		}
		ht = NULL;
	} else
		ht = vuht_pick(CHECKPATH, extra->path, &extra->statbuf, SET_EPOCH);
	printkdebug(c, "path %s: %c ht %p err = %d %s", extra->path, 
			nested ? 'N' : '-', ht,
			(sd->action == SKIPIT) ? -sd->ret_value : 0,
			(sd->action == SKIPIT) ? "SKIPIT" : "");
	if (ht)
		extra->mpath = vuht_path2mpath(ht, extra->path);
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
	if (ht) {
		extra->mpath = vuht_path2mpath(ht, extra->path);
		set_vepoch(vuht_get_vepoch(ht));
		vuht_pick_again(ht);
	}
	return ht;
}

struct vuht_entry_t *choice_ioctl(struct syscall_descriptor_t *sd) {
  struct syscall_extra_t *extra = sd->extra;
  int fd = sd->syscall_args[0];
	unsigned long request = sd->syscall_args[1];
  int nested = extra->nested;
  struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
  char path[PATH_MAX];
  vu_fd_get_path(fd, nested, path, PATH_MAX);
  extra->path = strdup(path);
  extra->statbuf.st_mode = vu_fd_get_mode(fd, nested);
  if (ht) {
    set_vepoch(vuht_get_vepoch(ht));
    vuht_pick_again(ht);
  } else 
		ht = vuht_pick(CHECKIOCTL, &request, NULL, SET_EPOCH);
  printkdebug(c, "ioctl %d %s: %c ht %p", fd, extra->path,
      nested ? 'N' : '-', ht);
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
				sd->action = SKIPIT;
			}
			ht = NULL;
		} else {
			char *no_root_path = (extra->path[1] == 0) ? "" : extra->path;
			ht = vuht_pick(CHECKPATHEXACT, no_root_path, &extra->statbuf, SET_EPOCH);
		}
		printkdebug(c, "umount2 %s: - ht %p err = %d %s", extra->path, ht,
      (sd->action == SKIPIT) ? -sd->ret_value : 0,
      (sd->action == SKIPIT) ? "SKIPIT" : "");
		return ht;
	}
}

struct vuht_entry_t *choice_mmap(struct syscall_descriptor_t *sd) {
	struct syscall_extra_t *extra = sd->extra;
  int fd = sd->syscall_args[4];
  int nested = extra->nested;
  struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
  char path[PATH_MAX];
  vu_fd_get_path(fd, nested, path, PATH_MAX);
  extra->path = strdup(path);
  extra->statbuf.st_mode = vu_fd_get_mode(fd, nested);
  printkdebug(c, "mmap2 %d %s: %c ht %p", fd, extra->path,
      nested ? 'N' : '-', ht);
  if (ht) {
		extra->mpath = vuht_path2mpath(ht, extra->path);
    set_vepoch(vuht_get_vepoch(ht));
    vuht_pick_again(ht);
  }
  return ht;
}

struct vuht_entry_t *choice_fd2(struct syscall_descriptor_t *sd) {
  struct syscall_extra_t *extra = sd->extra;
  int fd = sd->syscall_args[2];
  int nested = extra->nested;
  struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
  char path[PATH_MAX];
  vu_fd_get_path(fd, nested, path, PATH_MAX);
  extra->path = strdup(path);
  extra->statbuf.st_mode = vu_fd_get_mode(fd, nested);
  printkdebug(c, "fd2 %d %s: %c ht %p", fd, extra->path,
      nested ? 'N' : '-', ht);
  if (ht) {
		extra->mpath = vuht_path2mpath(ht, extra->path);
    set_vepoch(vuht_get_vepoch(ht));
    vuht_pick_again(ht);
  }
  return ht;
}

struct vuht_entry_t *choice_socket(struct syscall_descriptor_t *sd) {
	struct syscall_extra_t *extra = sd->extra;
	int domain = sd->syscall_args[0];
  int nested = extra->nested;
	struct vuht_entry_t *ht = vuht_pick(CHECKSOCKET, &domain, NULL, SET_EPOCH);
	printkdebug(c, "socket: fam:%d %c ht %p", domain, nested ? 'N' : '-', ht);
	return ht;
}

struct vuht_entry_t *choice_sc(struct syscall_descriptor_t *sd) {
	int vu_syscall_number = vu_arch_table[sd->syscall_number];
	struct vuht_entry_t *ht = vuht_pick(CHECKSC, &vu_syscall_number, NULL, SET_EPOCH);
	printkdebug(c, "sc: call:%d vcall:%d ht %p", sd->syscall_number, vu_syscall_number, ht);
	return ht;
}


__attribute__((constructor))
	static void init(void) {
		debug_set_name(c, "CHOICE");
	}

