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
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/epoll.h>
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
#include <vu_wrap_rw_multiplex.h>
#include <vu_slow_calls.h>

#define MAX_SOCKADDR_LEN sizeof(struct sockaddr_storage)

void wi_socket(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int domain;
		int type;
		int protocol;
		int flags = 0;
		void *private = NULL;
		switch (syscall_number) {
			case __NR_socket:
				domain = sd->syscall_args[0];
				type = sd->syscall_args[1];
				protocol = sd->syscall_args[2];
				break;
			case __VVU_msocket:
				domain = sd->syscall_args[1];
				type = sd->syscall_args[2];
				protocol = sd->syscall_args[3];
				break;
		}
		if (type & SOCK_CLOEXEC)
			flags |= O_CLOEXEC;
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_socket)(domain, type, protocol, &private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		} else {
			struct vu_fnode_t *fnode;
			/* fake dev = 0, inode = sfd */
			sd->extra->statbuf.st_mode = (sd->extra->statbuf.st_mode & ~S_IFMT) | S_IFSOCK;
			sd->extra->statbuf.st_dev = 0;
			sd->extra->statbuf.st_ino = ret_value;
			fnode = vu_fnode_create(ht, sd->extra->path, &sd->extra->statbuf, 0, ret_value, private);
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
	}
}

void wo_socket(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
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
	}
	sd->ret_value = sd->orig_ret_value;
}

void vw_msocket(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht)
		wi_socket(ht, sd);
	else if (sd->extra->statbuf.st_mode == 0)
		sd->ret_value = -ENOENT;
	else
		sd->ret_value = -ENOTSUP;
}

static int socket_close_upcall(struct vuht_entry_t *ht, int sfd, void *private) {
	if (ht) {
		int ret_value;
		ret_value = service_syscall(ht, __VU_close)(sfd, private);
		vuht_drop(ht);
		return ret_value;
	} else
		return 0;
}

void wi_bind(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addraddr =  sd->syscall_args[1];
		void *addr;
		socklen_t addrlen = sd->syscall_args[2];
		if (addrlen > MAX_SOCKADDR_LEN)
			addrlen = MAX_SOCKADDR_LEN;
		vu_alloc_peek_local_arg(addraddr, addr, addrlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_bind)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

void wi_connect(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addraddr =  sd->syscall_args[1];
		void *addr;
		socklen_t addrlen = sd->syscall_args[2];
		if (addrlen > MAX_SOCKADDR_LEN)
			addrlen = MAX_SOCKADDR_LEN;
		vu_alloc_peek_local_arg(addraddr, addr, addrlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_connect)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

void wi_listen(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		int backlog = sd->syscall_args[1];
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_listen)(sfd, backlog, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

/* accept accept4 */
void wi_accept4(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int fd = sd->syscall_args[0];
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addraddr =  sd->syscall_args[1];
		void *addr;
		uintptr_t paddrlen = sd->syscall_args[2];
		socklen_t *addrlen;
		int flags = 0;
		int fflags = 0;
		if (!nested) {
			int fd = sd->syscall_args[0];
			struct slowcall *sc = vu_slowcall_in(ht, fd, EPOLLIN, nested);
      if (sc != NULL) {
				sd->inout = sc;
				if (vu_slowcall_test(sc) <= 0) {
					sd->action = BLOCKIT;
					return;
				} else
					vu_slowcall_out(sc, ht, fd, EPOLLIN, nested);
			}
		}
		vu_alloc_peek_local_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
		if (*addrlen > MAX_SOCKADDR_LEN)
			*addrlen = MAX_SOCKADDR_LEN;
		vu_alloc_local_arg(addraddr, addr, *addrlen, nested);
		if (syscall_number == __NR_accept4)
			flags = sd->syscall_args[3];
		if (flags & SOCK_CLOEXEC)
			fflags |= O_CLOEXEC;
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_accept4)(sfd, addr, addrlen, flags, private, &private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			struct vu_fnode_t *fnode;
			/* fake dev = 0, inode = sfd */
			sd->extra->statbuf.st_mode = (sd->extra->statbuf.st_mode & ~S_IFMT) | S_IFSOCK;
			sd->extra->statbuf.st_dev = 0;
			sd->extra->statbuf.st_ino = ret_value;
			fnode = vu_fnode_create(ht, sd->extra->path, &sd->extra->statbuf, 0, ret_value, private);
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
			vu_poke_arg(addraddr, addr, ret_value, nested);
			vu_poke_arg(paddrlen, addrlen, sizeof(addrlen), nested);
			sd->ret_value = ret_value;
		}
	}
}

void wd_accept4(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (sd->action == BLOCKIT) {
		struct slowcall *sc = sd->inout;
		sd->waiting_pid = vu_slowcall_during(sc);
	}
}

void wo_accept4(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (sd->action == BLOCKIT) {
		int nested = sd->extra->nested;
		struct slowcall *sc = sd->inout;
		/* standard args */
		int fd = sd->syscall_args[0];
		if (sc != NULL) {
			vu_slowcall_out(sc, ht, fd, EPOLLIN, nested);
			if (sd->waiting_pid != 0) {
				sd->ret_value = -EINTR;
				sd->action = SKIPIT;
				return;
			}
		}
		sd->action = DO_IT_AGAIN;
	} else {
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
		}
		sd->ret_value = sd->orig_ret_value;
	}
}

void wi_getsockname(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addraddr =  sd->syscall_args[1];
		void *addr;
		uintptr_t paddrlen = sd->syscall_args[2];
		socklen_t *addrlen;
		vu_alloc_peek_local_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
		if (*addrlen > MAX_SOCKADDR_LEN)
			*addrlen = MAX_SOCKADDR_LEN;
		vu_alloc_local_arg(addraddr, addr, *addrlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_getsockname)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			vu_poke_arg(addraddr, addr, *addrlen, nested);
			vu_poke_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
			sd->ret_value = ret_value;
		}
	}
}

void wi_getpeername(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t addraddr =  sd->syscall_args[1];
		void *addr;
		uintptr_t paddrlen = sd->syscall_args[2];
		socklen_t *addrlen;
		vu_alloc_peek_local_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
		if (*addrlen > MAX_SOCKADDR_LEN)
			*addrlen = MAX_SOCKADDR_LEN;
		vu_alloc_local_arg(addraddr, addr, *addrlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_getpeername)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			vu_poke_arg(addraddr, addr, *addrlen, nested);
			vu_poke_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
			sd->ret_value = ret_value;
		}
	}
}

/* sendto, send, sendmsg, sendmmsg */
void wo_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd);
void wi_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		if (!nested) {
			int fd = sd->syscall_args[0];
			struct slowcall *sc = vu_slowcall_in(ht, fd, EPOLLOUT, nested);
			if (sc != NULL) {
				sd->inout = sc;
				sd->action = BLOCKIT;
				return;
			}
		}
		wo_sendto(ht, sd);
	}
}

void wd_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct slowcall *sc = sd->inout;
	sd->waiting_pid = vu_slowcall_during(sc);
}

void _wo_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	/* standard args */
	int syscall_number = sd->syscall_number;
	int nested = sd->extra->nested;
	/* args */
	int fd = sd->syscall_args[0];
	uintptr_t addr =  sd->syscall_args[1];
	size_t bufsize = sd->syscall_args[2];
	int flags = (syscall_number != __NR_write) ? sd->syscall_args[3] : 0;
	uintptr_t dest_addraddr = (syscall_number == __NR_sendto) ? sd->syscall_args[4] : 0;
	socklen_t addrlen = (syscall_number == __NR_sendto) ? sd->syscall_args[5] : 0;
	void *dest_addr = NULL;
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	void *buf;
	ssize_t ret_value;
	vu_alloc_peek_arg(addr, buf, bufsize, nested);
	if (addrlen > MAX_SOCKADDR_LEN)
		addrlen = MAX_SOCKADDR_LEN;
	vu_alloc_peek_local_arg(dest_addraddr, dest_addr, addrlen, nested);
	sd->action = SKIPIT;
	ret_value = service_syscall(ht, __VU_sendto)(sfd, buf, bufsize, flags, dest_addr, addrlen, NULL, 0, private);
	if (ret_value < 0)
		sd->ret_value = -errno;
	else
		sd->ret_value = ret_value;
	vu_free_arg(buf, nested);
}

void _wo_sendmsg(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	/* standard args */
	int nested = sd->extra->nested;
	/* args */
	int fd = sd->syscall_args[0];
	uintptr_t msgaddr = sd->syscall_args[1];
	int flags = sd->syscall_args[2];
	struct msghdr *msg;
	uintptr_t dest_addraddr;
	void *dest_addr = NULL;
	uintptr_t iovaddr;
	struct iovec *iov;
	uintptr_t controladdr;
	void *control = NULL;
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	void *buf;
	size_t bufsize;
	ssize_t ret_value;
	vu_alloc_peek_local_arg(msgaddr, msg, sizeof(struct msghdr), nested);
	if (msg->msg_namelen > MAX_SOCKADDR_LEN)
		msg->msg_namelen = MAX_SOCKADDR_LEN;
	dest_addraddr = (uintptr_t) msg->msg_name;
	vu_alloc_peek_local_arg(dest_addraddr, dest_addr, msg->msg_namelen, nested);
	iovaddr = (uintptr_t) msg->msg_iov;
	vu_alloc_peek_iov_arg(iovaddr, iov, msg->msg_iovlen, buf, bufsize, nested);
	controladdr = (uintptr_t) msg->msg_control;
	vu_alloc_peek_arg(controladdr, control, msg->msg_controllen, nested);
	sd->action = SKIPIT;
	ret_value = service_syscall(ht, __VU_sendto)(sfd, buf, bufsize, flags,
			dest_addr, msg->msg_namelen, control, msg->msg_controllen, private);
	if (ret_value < 0)
		sd->ret_value = -errno;
	else
		sd->ret_value = ret_value;
	vu_free_iov_arg(iov, buf, nested);
	vu_free_arg(control, nested);
}

void _wo_sendmmsg(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = -ENOSYS;
	sd->action = SKIPIT;
}

void wo_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	struct slowcall *sc = sd->inout;
	/* standard args */
	int syscall_number = sd->syscall_number;
	int fd = sd->syscall_args[0];
	if (sc != NULL) {
		vu_slowcall_out(sc, ht, fd, EPOLLOUT, nested);
		if (sd->waiting_pid != 0) {
			sd->ret_value = -EINTR;
			sd->action = SKIPIT;
			return;
		}
	}
	switch (syscall_number) {
		case __NR_write:
		case __NR_sendto:
			_wo_sendto(ht, sd);
			break;
		case __NR_sendmsg:
			_wo_sendmsg(ht, sd);
			break;
		case __NR_sendmmsg:
			_wo_sendmmsg(ht, sd);
			break;
	}
}

/* recvfrom, recv, recvmsg, recvmmsg */
void wo_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd);
void wi_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		if (!nested) {
			int fd = sd->syscall_args[0];
			struct slowcall *sc = vu_slowcall_in(ht, fd, EPOLLIN, nested);
			if (sc != NULL) {
				sd->inout = sc;
				sd->action = BLOCKIT;
				return;
			}
		}
		wo_recvfrom(ht, sd);
	}
}

void wd_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct slowcall *sc = sd->inout;
	sd->waiting_pid = vu_slowcall_during(sc);
}

void _wo_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	/* standard args */
	int syscall_number = sd->syscall_number;
	int nested = sd->extra->nested;
	/* args */
	int fd = sd->syscall_args[0];
	uintptr_t addr =  sd->syscall_args[1];
	size_t bufsize = sd->syscall_args[2];
	int flags = (syscall_number != __NR_read) ? sd->syscall_args[3] : 0;
	uintptr_t src_addraddr = (syscall_number == __NR_recvfrom) ? sd->syscall_args[4] : 0;
	uintptr_t paddrlen = (syscall_number == __NR_recvfrom) ? sd->syscall_args[5] : 0;
	socklen_t *addrlen;
	void *src_addr = NULL;
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	void *buf;
	ssize_t ret_value;
	vu_alloc_arg(addr, buf, bufsize, nested);
	vu_alloc_peek_local_arg(paddrlen, addrlen, sizeof(socklen_t), nested);
	if (*addrlen > MAX_SOCKADDR_LEN)
		*addrlen = MAX_SOCKADDR_LEN;
	vu_alloc_local_arg(src_addraddr, src_addr, *addrlen, nested);
	sd->action = SKIPIT;
	ret_value = service_syscall(ht, __VU_recvfrom)(sfd, buf, bufsize, flags, src_addr, addrlen, NULL, 0, private);
	if (ret_value < 0)
		sd->ret_value = -errno;
	else {
		sd->ret_value = ret_value;
		vu_poke_arg(addr, buf, bufsize, nested);
		vu_poke_arg(src_addraddr, src_addr, ret_value, nested);
		vu_poke_arg(paddrlen, addrlen, sizeof(addrlen), nested);
	}
	vu_free_arg(buf, nested);
}

void _wo_recvmsg(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	/* standard args */
	int nested = sd->extra->nested;
	/* args */
	int fd = sd->syscall_args[0];
	uintptr_t msgaddr = sd->syscall_args[1];
	int flags = sd->syscall_args[2];
	struct msghdr *msg;
	uintptr_t src_addraddr;
	void *src_addr = NULL;
	uintptr_t iovaddr;
	struct iovec *iov;
	uintptr_t controladdr;
	void *control = NULL;
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	void *buf;
	size_t bufsize;
	ssize_t ret_value;
	vu_alloc_peek_local_arg(msgaddr, msg, sizeof(struct msghdr), nested);
	if (msg->msg_namelen > MAX_SOCKADDR_LEN)
		msg->msg_namelen = MAX_SOCKADDR_LEN;
	src_addraddr = (uintptr_t) msg->msg_name;
	vu_alloc_local_arg(src_addraddr, src_addr, msg->msg_namelen, nested);
	iovaddr = (uintptr_t) msg->msg_iov;
	vu_alloc_iov_arg(iovaddr, iov, msg->msg_iovlen, buf, bufsize, nested);
	controladdr = (uintptr_t) msg->msg_control;
	vu_alloc_arg(controladdr, control, msg->msg_controllen, nested);
	sd->action = SKIPIT;
	ret_value = service_syscall(ht, __VU_recvfrom)(sfd, buf, bufsize, flags,
			src_addr, &msg->msg_namelen, control, &msg->msg_controllen, private);
	if (ret_value < 0)
		sd->ret_value = -errno;
	else {
		sd->ret_value = ret_value;
		vu_poke_iov_arg(iovaddr, iov, msg->msg_iovlen, buf, ret_value, nested);
		vu_poke_arg(controladdr, control, msg->msg_controllen, nested);
		vu_poke_arg(src_addraddr, src_addr, msg->msg_namelen, nested);
		vu_poke_arg(msgaddr, msg, sizeof(struct msghdr), nested);
	}
	vu_free_iov_arg(iov, buf, nested);
	vu_free_arg(control, nested);
}

void _wo_recvmmsg(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = -ENOSYS;
	sd->action = SKIPIT;
}

void wo_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	struct slowcall *sc = sd->inout;
	/* standard args */
	int syscall_number = sd->syscall_number;
	int fd = sd->syscall_args[0];
	if (sc != NULL) {
		vu_slowcall_out(sc, ht, fd, EPOLLIN, nested);
		if (sd->waiting_pid != 0) {
			sd->ret_value = -EINTR;
			sd->action = SKIPIT;
			return;
		}
	}
	switch (syscall_number) {
		case __NR_read:
		case __NR_recvfrom:
			_wo_recvfrom(ht, sd);
			break;
		case __NR_recvmsg:
			_wo_recvmsg(ht, sd);
			break;
		case __NR_recvmmsg:
			_wo_recvmmsg(ht, sd);
			break;
	}
}

void wi_shutdown(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		int how = sd->syscall_args[1];
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_shutdown)(sfd, how, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

void wi_setsockopt(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int level = sd->syscall_args[1];
		int optname = sd->syscall_args[2];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t optvaladdr =  sd->syscall_args[3];
		socklen_t optlen = sd->syscall_args[4];
		void *optval;
		vu_alloc_peek_arg(optvaladdr, optval, optlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_setsockopt)(sfd, level, optname, optval, optlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
		vu_free_arg(optval, nested);
	}
}

void wi_getsockopt(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int ret_value;
		int fd = sd->syscall_args[0];
		int level = sd->syscall_args[1];
		int optname = sd->syscall_args[2];
		int nested = sd->extra->nested;
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		uintptr_t optvaladdr =  sd->syscall_args[3];
		uintptr_t optlenaddr =  sd->syscall_args[4];
		void *optval;
		socklen_t *optlen;
		vu_alloc_peek_local_arg(optlenaddr, optlen, sizeof(socklen_t), nested);
		vu_alloc_arg(optvaladdr, optval, *optlen, nested);
		sd->action = SKIPIT;
		ret_value = service_syscall(ht, __VU_getsockopt)(sfd, level, optname, optval, optlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			sd->ret_value = ret_value;
			vu_poke_arg(optvaladdr, optval, *optlen, nested);
		}
		vu_free_arg(optval, nested);
	}
}

__attribute__((constructor))
	static void init(void) {
		vu_fnode_set_close_upcall(S_IFSOCK, socket_close_upcall);
		multiplex_read_wrappers(S_IFSOCK, wi_recvfrom, wd_recvfrom, wo_recvfrom);
		multiplex_write_wrappers(S_IFSOCK, wi_sendto, wd_sendto, wo_sendto);
	}
