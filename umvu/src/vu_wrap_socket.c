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

#define MAX_SOCKADDR_LEN sizeof(struct sockaddr_storage)

void wi_msocket(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  int nested = sd->extra->nested;
	if (ht) {
		/* standard args */
    int syscall_number = sd->syscall_number;
    int ret_value;
    /* args */
		int domain = sd->syscall_args[0];
		int type = sd->syscall_args[1];
		int protocol = sd->syscall_args[2];
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
		sd->action = SKIP;
    ret_value = service_syscall(ht, __VU_open)(sd->extra->path, domain, type, protocol, &private);
		if (ret_value < 0) {
      sd->ret_value = -errno;
      return;
    } else {
			struct fnode_t *fnode;
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

void wo_msocket(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  int fd = sd->orig_ret_value;
  if (ht) {
    struct fnode_t *fnode = sd->inout;
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
		wi_msocket(ht, sd);
  else
		sd->ret_value = -EINVAL;
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
		sd->action = SKIP;
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
		sd->action = SKIP;
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
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_listen)(sfd, backlog, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	}
}

/* accept is a slow call TODO XXX */
void wi_accept4(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		sd->ret_value = -ENOSYS;
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
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_getsockname)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			vu_poke_arg(addraddr, addr, ret_value, nested);
			vu_poke_arg(paddrlen, addrlen, sizeof(addrlen), nested);
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
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_getpeername)(sfd, addr, addrlen, private);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else {
			vu_poke_arg(addraddr, addr, ret_value, nested);
			vu_poke_arg(paddrlen, addrlen, sizeof(addrlen), nested);
			sd->ret_value = ret_value;
		}
	}
}

void wi_sendto(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		sd->ret_value = -ENOSYS;
	}
}

void wi_recvfrom(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		sd->ret_value = -ENOSYS;
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
		sd->action = SKIP;
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
    sd->action = SKIP;
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
		sd->action = SKIP;
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
