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
#include <sys/uio.h>
#include <fcntl.h>
#include <dirent.h>

#include <linux_32_64.h>
#include <vu_log.h>
#include <r_table.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <epoch.h>
#include <path_utils.h>
#include <vu_fs.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <vu_wrap_rw_multiplex.h>
#include <vu_wrapper_utils.h>
#include <vu_slow_calls.h>

/* open, creat, openat */
/* all open files are registered in the file tables.
 * if the file is virtualized:
 *    wi_open creates the f-node and then wo_open registers it in the fdtable.
 *    the path of the real opensystem call is diverted to the tmpfile (see vnode.c)
 * otherwise:
 *    if the real syscall request succeeds: wo_open creates an fnode and
 *    registers it in the fdtable
 */

void wi_open(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int flags;
		int mode;
		void *private = NULL;
		/* local bufs */
		/* fetch args */
		switch (syscall_number) {
			case __NR_open:
				flags = sd->syscall_args[1];
				mode = (flags & O_CREAT) || (flags & O_TMPFILE) ?
					sd->syscall_args[2] : 0;
				break;
			case __NR_creat:
				flags = O_CREAT|O_WRONLY|O_TRUNC;
				mode = sd->syscall_args[1];
				break;
			case __NR_openat:
				flags = sd->syscall_args[2];
				mode = (flags & O_CREAT) || (flags & O_TMPFILE) ?
					sd->syscall_args[3] : 0;
		}
		mode = mode & ~vu_fs_get_umask();
		/* call */
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_open)(sd->extra->mpath, flags, mode, &private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		} else {
			struct vu_fnode_t *fnode;
			if (sd->extra->statbuf.st_mode == 0) /* new file just created */
				service_syscall(ht, __VU_lstat)(sd->extra->mpath, &sd->extra->statbuf, AT_SYMLINK_NOFOLLOW, ret_value, private);
			fnode = vu_fnode_create(ht, sd->extra->path, &sd->extra->statbuf, flags, ret_value, private);
			vuht_pick_again(ht);
			if (nested) {
				/* do not use DOIT_CB_AFTER: open must be real, not further virtualized */
				int fd;
				sd->ret_value = fd = r_open(vu_fnode_get_vpath(fnode), O_CREAT | O_RDWR, 0600);
				if (fd >= 0)
					vu_fd_set_fnode(fd, nested, fnode, flags);
				else
					vu_fnode_close(fnode);
			} else {
				sd->inout = fnode;
				sd->ret_value = ret_value;
				/* change the call to "open(vopen, O_CREAT | O_RDWR, 0600)" */
				sd->syscall_number = __NR_open;
				rewrite_syspath(sd, vu_fnode_get_vpath(fnode));
				sd->syscall_args[1] = O_CREAT | O_RDWR | (flags & O_CLOEXEC);
				sd->syscall_args[2] = 0600;
				sd->action = DOIT_CB_AFTER;
			}
		}
	} else
		sd->action = DOIT_CB_AFTER;
}

void wo_open(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int fd = sd->orig_ret_value;
	if (ht) {
		struct vu_fnode_t *fnode = sd->inout;
		int fdflags = sd->syscall_args[1] & O_CLOEXEC ? FD_CLOEXEC : 0;
		if (fd >= 0) {
			vu_fd_set_fnode(fd, VU_NOT_NESTED, fnode, fdflags);
		} else {
			vu_fnode_close(fnode);
			vuht_drop(ht);
		}
	} else {
		if (fd >= 0) {
			struct vu_fnode_t *fnode;
			int fdflags;
			int nested = sd->extra->nested;
			switch (sd->syscall_number) {
				case __NR_open: fdflags = sd->syscall_args[1] & O_CLOEXEC ? FD_CLOEXEC : 0;
												break;
				case __NR_openat: fdflags = sd->syscall_args[1] & O_CLOEXEC ? FD_CLOEXEC : 0;
													break;
				default: fdflags = 0;
			}
			if (sd->extra->statbuf.st_mode == 0) /* new file just created */
				r_lstat(sd->extra->path, &sd->extra->statbuf);
			fnode = vu_fnode_create(NULL, sd->extra->path, &sd->extra->statbuf, 0, -1, NULL);
			vu_fd_set_fnode(fd, nested, fnode, fdflags);
		}
	}
	sd->ret_value = sd->orig_ret_value;
}

/* close */
void wi_close(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (nested) {
		/* do not use DOIT_CB_AFTER: close must be real, not further virtualized */
		int fd = sd->syscall_args[0];
		int ret_value = vu_fd_close(fd, VU_NESTED);
		sd->ret_value = ret_value < 0 ? -errno : 0;
		r_close(fd);
		sd->action = SKIPIT;
	} else {
		sd->action = DOIT_CB_AFTER;
	}
}

void wo_close(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int fd = sd->syscall_args[0];
	int ret_value = sd->orig_ret_value;
	if (ret_value >= 0)
		vu_fd_close(fd, VU_NOT_NESTED);
	sd->ret_value = sd->orig_ret_value;
}

static int file_close_upcall(struct vuht_entry_t *ht, int sfd, void *private) {
	if (ht) {
		int ret_value;
		struct vuht_entry_t *sht = vu_mod_getht();
		epoch_t e = get_vepoch();
		set_vepoch(vuht_get_vepoch(ht));
		vu_mod_setht(ht);
		ret_value = service_syscall(ht, __VU_close)(sfd, private);
		vu_mod_setht(sht);
		vuht_drop(ht);
		set_vepoch(e);
		return ret_value;
	} else
		return 0;
}

/* read, readv */
static void _file_wx_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int fd = sd->syscall_args[0];
	int nested = sd->extra->nested;
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	if (sd->syscall_number == __NR_read) {
		uintptr_t addr =  sd->syscall_args[1];
		size_t bufsize = sd->syscall_args[2];
		void *buf;
		ssize_t ret_value;
		vu_alloc_arg(addr, buf, bufsize, nested);
		ret_value = service_syscall(ht, __VU_read)(sfd, buf, bufsize, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			sd->ret_value = ret_value;
			if (ret_value > 0)
				vu_poke_arg(addr, buf, ret_value, nested);
		}
		vu_free_arg(buf, nested);
	} else { // readv
		uintptr_t iovaddr = sd->syscall_args[1];
		int iovcnt = sd->syscall_args[2];
		struct iovec *iov;
		void *buf;
		ssize_t ret_value;
		size_t bufsize;
		vu_alloc_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested);
		ret_value = service_syscall(ht, __VU_read)(sfd, buf, bufsize, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			sd->ret_value = ret_value;
			vu_poke_iov_arg(iovaddr, iov, iovcnt, buf, ret_value, nested);
		}
		vu_free_iov_arg(iov, buf, nested);
	}
}

void file_wi_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		_file_wx_read(ht, sd);
		sd->action = SKIPIT;
	}
}

void slow_wi_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		if (!nested) {
			int fd = sd->syscall_args[0];
			struct slowcall *sc = vu_slowcall_in(ht, fd, EPOLLIN, nested);
			if (sc != NULL) {
				sd->inout = sc;
				sd->action = BLOCKIT;
				return;
			}
		}
		_file_wx_read(ht, sd);
		sd->action = SKIPIT;
	}
}

void slow_wd_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct slowcall *sc = sd->inout;
	sd->waiting_pid = vu_slowcall_during(sc);
}

void slow_wo_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	struct slowcall *sc = sd->inout;
	int fd = sd->syscall_args[0];
	if (sc != NULL) {
		vu_slowcall_out(sc, ht, fd, EPOLLIN, nested);
		if (sd->waiting_pid != 0) {
			sd->ret_value = -EINTR;
			sd->action = SKIPIT;
			return;
		}
	}
	_file_wx_read(ht, sd);
}

/* write, writev */
static void _file_wx_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		if (sd->syscall_number == __NR_write) {
			uintptr_t addr =  sd->syscall_args[1];
			size_t bufsize = sd->syscall_args[2];
			void *buf;
			ssize_t ret_value;
			vu_alloc_peek_arg(addr, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_write)(sfd, buf, bufsize, private);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else
				sd->ret_value = ret_value;
			vu_free_arg(buf, nested);
		} else { // writev
			uintptr_t iovaddr = sd->syscall_args[1];
			int iovcnt = sd->syscall_args[2];
			struct iovec *iov;
			void *buf;
			ssize_t ret_value;
			size_t bufsize;
			vu_alloc_peek_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_write)(sfd, buf, bufsize, private);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else
				sd->ret_value = ret_value;
			vu_free_iov_arg(iov, buf, nested);
		}
		sd->action = SKIPIT;
	}
}

void file_wi_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		_file_wx_write(ht, sd);
		sd->action = SKIPIT;
	}
}

void slow_wi_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		if (!nested) {
			int fd = sd->syscall_args[0];
			struct slowcall *sc = vu_slowcall_in(ht, fd, EPOLLOUT, nested);
			if (sc != NULL) {
				sd->inout = sc;
				sd->action = BLOCKIT;
				return;
			}
		}
		_file_wx_write(ht, sd);
		sd->action = SKIPIT;
	}
}

void slow_wd_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct slowcall *sc = sd->inout;
	sd->waiting_pid = vu_slowcall_during(sc);
}

void slow_wo_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	struct slowcall *sc = sd->inout;
	int fd = sd->syscall_args[0];
	if (sc != NULL) {
		vu_slowcall_out(sc, ht, fd, EPOLLIN, nested);
		if (sd->waiting_pid != 0) {
			sd->ret_value = -EINTR;
			sd->action = SKIPIT;
			return;
		}
	}
	_file_wx_write(ht, sd);
}

/* pread64, preadv, preadv2 */
void wi_pread(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		int flags = 0;
		if (sd->syscall_number == __NR_pread64) {
			uintptr_t addr =  sd->syscall_args[1];
			size_t bufsize = sd->syscall_args[2];
			off_t offset = sd->syscall_args[3];
			void *buf;
			ssize_t ret_value;
			vu_alloc_arg(addr, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_pread64)(sfd, buf, bufsize, offset, flags, private);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else {
				sd->ret_value = ret_value;
				if (ret_value > 0)
					vu_poke_arg(addr, buf, ret_value, nested);
			}
			vu_free_arg(buf, nested);
		} else { // preadv, preadv2
			uintptr_t iovaddr = sd->syscall_args[1];
			int iovcnt = sd->syscall_args[2];
			off_t offset = sd->syscall_args[3];
#ifdef __NR_preadv2
			if (sd->syscall_number == __NR_preadv2)
				flags = sd->syscall_args[4];
#endif
			struct iovec *iov;
			void *buf;
			ssize_t ret_value;
			size_t bufsize;
			vu_alloc_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_pread64)(sfd, buf, bufsize, offset, flags, private);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else {
				sd->ret_value = ret_value;
				vu_poke_iov_arg(iovaddr, iov, iovcnt, buf, ret_value, nested);
			}
			vu_free_iov_arg(iov, buf, nested);
		}
		sd->action = SKIPIT;
	}
}

/* pwrite64, pwritev, pwritev2 */
void wi_pwrite(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		int flags = 0;
		if (sd->syscall_number == __NR_pwrite64) {
			uintptr_t addr =  sd->syscall_args[1];
			size_t bufsize = sd->syscall_args[2];
			off_t offset = sd->syscall_args[3];
			void *buf;
			ssize_t ret_value;
			vu_alloc_peek_arg(addr, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_pwrite64)(sfd, buf, bufsize, offset, flags, private);
			vu_free_arg(buf, nested);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else
				sd->ret_value = ret_value;
		} else { // pwritev, pwritev2
			uintptr_t iovaddr = sd->syscall_args[1];
			int iovcnt = sd->syscall_args[2];
			off_t offset = sd->syscall_args[3];
#ifdef __NR_pwritev2
			if (sd->syscall_number == __NR_pwritev2)
				flags = sd->syscall_args[4];
#endif
			struct iovec *iov;
			void *buf;
			ssize_t ret_value;
			size_t bufsize;
			vu_alloc_peek_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested);
			ret_value = service_syscall(ht, __VU_pwrite64)(sfd, buf, bufsize, offset, flags, private);
			if (ret_value < 0)
				sd->ret_value = -errno;
			else
				sd->ret_value = ret_value;
			vu_free_iov_arg(iov, buf, nested);
		}
		sd->action = SKIPIT;
	}
}

/* getdents64, getdents */
void wi_getdents64(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addr =  sd->syscall_args[1];
		unsigned int bufsize = sd->syscall_args[2];
		void *buf;
		int ret_value;
		vu_alloc_arg(addr, buf, bufsize, nested);
		ret_value = service_syscall(ht, __VU_getdents64)(sfd, buf, bufsize, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			if (sd->syscall_number == __NR_getdents)
				dirent64_to_dirent(buf, ret_value);
			vu_poke_arg(addr, buf, ret_value, nested);
			sd->ret_value = ret_value;
		}
		vu_free_arg(buf, nested);
		sd->action = SKIPIT;
	}
}

/* dup, dup2, dup3 */
void wi_dup3(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (nested) {
		int fd = sd->syscall_args[0];
		int newfd;
		int flags;
		switch (sd->syscall_number) {
			case __NR_dup: newfd = r_dup(fd);
										 break;
			case __NR_dup2: newfd = sd->syscall_args[1];
											newfd = r_dup2(fd, newfd);
											break;
			case __NR_dup3: newfd = sd->syscall_args[1];
											flags = sd->syscall_args[2];
											newfd = r_dup3(fd, newfd, flags);
		}
		sd->action = SKIPIT;
		if (newfd < 0)
			sd->ret_value = -errno;
		else {
			if (newfd != fd)
				vu_fd_dup(newfd, VU_NESTED, fd, flags);
			sd->ret_value = newfd;
		}
	} else {
		sd->action = DOIT_CB_AFTER;
	}
}

void wo_dup3(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int newfd = sd->orig_ret_value;
	int fd = sd->syscall_args[0];
	if (newfd >= 0 && fd != newfd) { //dup2 does nothing if fd == newfd
		int flags = 0;
		if (sd->syscall_number == __NR_dup3)
			flags = sd->syscall_args[2];
		vu_fd_dup(newfd, VU_NOT_NESTED, fd, flags);
	}
	sd->ret_value = newfd;
}

void wi_fcntl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int fd = sd->syscall_args[0];
	int cmd = sd->syscall_args[1];
	int ret_value;
	if (ht) {
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		switch (cmd) { /* common mgmt virtual fd*/
			case F_GETFD:
				ret_value = vu_fd_get_fdflags(fd, nested);
				sd->ret_value = (ret_value < 0) ? -EBADF : ret_value;
				sd->action = SKIPIT;
				return;
			case F_SETFD:
				{
					int flags = sd->syscall_args[2];
					vu_fd_set_fdflags(fd, nested, flags);
					sd->ret_value = 0;
					/* DO IT */
				}
				return;
			case F_GETFL:
				ret_value = service_syscall(ht, __VU_fcntl)(sfd, F_GETFL, 0, private);
				if (ret_value < 0) {
					sd->ret_value = -errno;
					if (errno == ENOSYS)
						sd->ret_value = vu_fd_get_flflags(fd, nested);
				}
				else
					sd->ret_value = ret_value;
				sd->action = SKIPIT;
				return;
			case F_SETFL:
				{
					int flags = sd->syscall_args[2];
					ret_value = service_syscall(ht, __VU_fcntl)(sfd, F_SETFL, flags, private);
					if (ret_value < 0) {
						sd->ret_value = -errno;
					} else {
						sd->ret_value = ret_value;
						vu_fd_set_flflags(fd, nested, flags);
					}
				}
				return;
		}
	} else {
		switch (cmd) { /* common mgmt real fd*/
			case F_GETFD:
			case F_GETFL:
				return; /* DOIT */
			case F_SETFD:
			case F_SETFL:
				sd->action = DOIT_CB_AFTER;
				return;
		}
	}
	if (nested) {
		switch(cmd) {
			case F_DUPFD:
			case F_DUPFD_CLOEXEC:
				{
					int newfd;
					int arg = sd->syscall_args[2];
					int flags = (cmd == F_DUPFD_CLOEXEC) ? FD_CLOEXEC : 0;
					newfd = fcntl(fd, cmd, arg);
					sd->action = SKIPIT;
					if (newfd < 0)
						sd->ret_value = -errno;
					else {
						if (newfd != fd)
							vu_fd_dup(newfd, VU_NESTED, fd, flags);
						sd->ret_value = newfd;
					}
				}
				return;
		}
	} else {
		switch(cmd) {
			case F_DUPFD:
			case F_DUPFD_CLOEXEC:
				sd->action = DOIT_CB_AFTER;
				return;
		}
	}
}

void wd_fcntl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wo_fcntl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int fd = sd->syscall_args[0];
	int cmd = sd->syscall_args[1];
	int ret_value = sd->orig_ret_value;
	switch(cmd) {
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			{
				int newfd = ret_value;
				int flags = (cmd == F_DUPFD_CLOEXEC) ? FD_CLOEXEC : 0;
				if (newfd >= 0 && fd != newfd)
					vu_fd_dup(newfd, VU_NOT_NESTED, fd, flags);
			}
			break;
		case F_SETFD:
			{
				int flags = sd->syscall_args[2];
				if (ret_value >= 0)
					vu_fd_set_fdflags(fd, nested, flags);
			}
			break;
		case F_SETFL:
			{
				int flags = sd->syscall_args[2];
				if (ret_value >= 0)
					vu_fd_set_flflags(fd, nested, flags);
			}
			break;
	}
	sd->ret_value = ret_value;
}

/* umask */
/* umask always succeeds. just copy the value */
void wi_umask(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		int umask = sd->syscall_args[0];
		vu_fs_set_umask(umask);
	}
}

/* lseek */
void wi_lseek(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		off_t ret_value;
		/* args */
		int fd = sd->syscall_args[0];
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		off_t offset = sd->syscall_args[1];
		int whence = sd->syscall_args[2];
		/* call */
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_lseek)(sfd, offset, whence, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

void wi_sendfile(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->action = SKIPIT;
	sd->ret_value = -ENOSYS;
}

__attribute__((constructor))
	static void init(void) {
		vu_fnode_set_close_upcall(S_IFREG, file_close_upcall);
		vu_fnode_set_close_upcall(S_IFDIR, file_close_upcall);
		vu_fnode_set_close_upcall(S_IFCHR, file_close_upcall);
		vu_fnode_set_close_upcall(S_IFBLK, file_close_upcall);
		vu_fnode_set_close_upcall(S_IFLNK, file_close_upcall);
		multiplex_read_wrappers(S_IFREG, file_wi_read, NULL, NULL);
		multiplex_read_wrappers(S_IFBLK, file_wi_read, NULL, NULL);
		multiplex_read_wrappers(S_IFCHR, slow_wi_read, slow_wd_read, slow_wo_read);
		multiplex_write_wrappers(S_IFREG, file_wi_write, NULL, NULL);
		multiplex_write_wrappers(S_IFBLK, file_wi_write, NULL, NULL);
		multiplex_write_wrappers(S_IFCHR, slow_wi_write, slow_wd_write, slow_wo_write);
	}
