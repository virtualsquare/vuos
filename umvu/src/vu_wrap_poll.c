#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <signal.h>
#include <poll.h>

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

struct poll_inout {
	nfds_t nfds;
	struct pollfd *fds;
	struct pollfd *fds_real;
	struct pollfd *fds_virt;
	int poll_rv;
};

void wi_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		struct poll_inout *pollio = malloc(sizeof(struct poll_inout));
		uintptr_t fdsaddr =  sd->syscall_args[0];
		nfds_t i, nvirt;
		fatal(pollio);
		pollio->nfds = sd->syscall_args[1];
		vu_alloc_peek_arg(fdsaddr, pollio->fds, pollio->nfds * sizeof(struct pollfd), nested);
		pollio->fds_real = malloc(pollio->nfds * sizeof(struct pollfd));
		fatal(pollio->fds_real);
		pollio->fds_virt = malloc(pollio->nfds * sizeof(struct pollfd));
		fatal(pollio->fds_virt);
		for (i = nvirt = 0; i < pollio->nfds; i++) {
			int fd = pollio->fds[i].fd;
			struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
			pollio->fds_real[i] = pollio->fds_virt[i] = pollio->fds[i];
			if (ht) {
				void *private;
				int sfd = vu_fd_get_sfd(fd, &private, nested);
				nvirt++;
				vuht_pick_again(ht);
				pollio->fds_real[i].fd = -1;
				pollio->fds_virt[i].fd = sfd;
			} else
				pollio->fds_virt[i].fd = -1;
		}
		if (nvirt == 0) {
			xfree(pollio->fds_real);
			xfree(pollio->fds_virt);
			vu_free_arg(pollio->fds, nested);
			xfree(pollio);
		} else {
			sd->action = DOIT_CB_AFTER;
			sd->inout = pollio;
			vu_poke_arg(fdsaddr, pollio->fds_real, pollio->nfds * sizeof(struct pollfd), nested);
		}
	}
}

void wd_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct poll_inout *pollio = sd->inout;
	sigset_t sm;
  sigemptyset(&sm);
	pollio->poll_rv = r_ppoll(pollio->fds_virt, pollio->nfds, NULL, &sm);
	if (pollio->poll_rv > 0 || errno != EINTR) {
		umvu_unblock();
	}
}

void wo_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	uintptr_t fdsaddr =  sd->syscall_args[0];
	struct poll_inout *pollio = sd->inout;
	nfds_t i;
	int orig_ret_value = sd->orig_ret_value;
	int ret_value;
	vu_peek_arg(fdsaddr, pollio->fds_real, pollio->nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	for (i = 0, ret_value = 0; i < pollio->nfds; i++) {
		int fd = pollio->fds[i].fd;
		struct vuht_entry_t *ht = vu_fd_get_ht(fd, VU_NOT_NESTED);
		if (ht) {
			vuht_drop(ht);
			pollio->fds[i].revents = pollio->fds_virt[i].revents;
		} else {
			pollio->fds[i].revents = pollio->fds_real[i].revents;
		}
		if (pollio->fds[i].revents != 0)
			ret_value++;
	}
	vu_poke_arg(fdsaddr, pollio->fds, pollio->nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	if (orig_ret_value == -1 && pollio->poll_rv == -1)
		sd->ret_value = -1;
	else
		sd->ret_value = ret_value;
	xfree(pollio->fds_real);
	xfree(pollio->fds_virt);
	vu_free_arg(pollio->fds, VU_NOT_NESTED);
	xfree(pollio);
}

struct select_inout {
  nfds_t nfds;
  struct pollfd *fds_virt;
  int select_rv;
};

void wi_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
    //struct poll_inout *pollio = malloc(sizeof(struct poll_inout));
		int nfds = sd->syscall_args[0];
		int fd;
		nfds_t nvirt;
		uintptr_t readfdsaddr = sd->syscall_args[1];
		uintptr_t writefdsaddr = sd->syscall_args[2];
		uintptr_t exceptfdsaddr = sd->syscall_args[3];
		fd_set *readfds, *writefds, *exceptfds;
		vu_alloc_peek_arg(readfdsaddr, readfds, sizeof(fd_set), nested);
		vu_alloc_peek_arg(writefdsaddr, writefds, sizeof(fd_set), nested);
		vu_alloc_peek_arg(exceptfdsaddr, exceptfds, sizeof(fd_set), nested);
		for (fd = nvirt = 0; fd < nfds; fd++) {
			if ((FD_ISSET(fd, readfds) || FD_ISSET(fd, writefds) ||
						FD_ISSET(fd, exceptfds)) && vu_fd_get_ht(fd, nested) != NULL)
				nvirt++;
		}
		if (nvirt != 0) {
			struct select_inout *selectio = malloc(sizeof(struct poll_inout));
			fatal(selectio);
			selectio->nfds=0;
			selectio->fds_virt = malloc(nvirt * sizeof(struct pollfd));
			for (fd = selectio->nfds = 0; fd < nfds && selectio->nfds < nvirt; fd++) {
				if ((FD_ISSET(fd, readfds) || FD_ISSET(fd, writefds) ||
            FD_ISSET(fd, exceptfds)) && vu_fd_get_ht(fd, nested) != NULL) {
					selectio->fds_virt[selectio->nfds].fd = fd;
					selectio->fds_virt[selectio->nfds].events = 
						(FD_ISSET(fd, readfds) ? POLLIN : 0) |
						(FD_ISSET(fd, writefds) ? POLLOUT : 0) |
						(FD_ISSET(fd, exceptfds) ? POLLPRI : 0);
					selectio->nfds++;
					FD_CLR(fd, readfds);
					FD_CLR(fd, writefds);
					FD_CLR(fd, exceptfds);
				}
			}
			sd->action = DOIT_CB_AFTER;
      sd->inout = selectio;
			vu_poke_arg(readfdsaddr, readfds, sizeof(fd_set), nested);
			vu_poke_arg(writefdsaddr, writefds, sizeof(fd_set), nested);
			vu_poke_arg(exceptfdsaddr, exceptfds, sizeof(fd_set), nested);
    }
		vu_free_arg(readfds, nested);
		vu_free_arg(writefds, nested);
		vu_free_arg(exceptfds, nested);
  }
}

void wd_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct select_inout *selectio = sd->inout;
  sigset_t sm;
  sigemptyset(&sm);
  selectio->select_rv = r_ppoll(selectio->fds_virt, selectio->nfds, NULL, &sm);
  if (selectio->select_rv > 0 || errno != EINTR) {
    umvu_unblock();
  }
}

void wo_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	nfds_t i;
	uintptr_t readfdsaddr = sd->syscall_args[1];
	uintptr_t writefdsaddr = sd->syscall_args[2];
	uintptr_t exceptfdsaddr = sd->syscall_args[3];
	fd_set *readfds, *writefds, *exceptfds;
  struct select_inout *selectio = sd->inout;
  int orig_ret_value = sd->orig_ret_value;
  int ret_value;
	vu_alloc_peek_arg(readfdsaddr, readfds, sizeof(fd_set), VU_NOT_NESTED);
	vu_alloc_peek_arg(writefdsaddr, writefds, sizeof(fd_set), VU_NOT_NESTED);
	vu_alloc_peek_arg(exceptfdsaddr, exceptfds, sizeof(fd_set), VU_NOT_NESTED);
  for (i = 0, ret_value = 0; i < selectio->nfds; i++) {
    int fd = selectio->fds_virt[i].fd;
		if (selectio->fds_virt[i].revents) {
			struct vuht_entry_t *ht = vu_fd_get_ht(fd, VU_NOT_NESTED);
			if (ht) {
				if (selectio->fds_virt[i].revents & POLLIN) {
					FD_SET(fd, readfds);
					ret_value++;
				}
				if (selectio->fds_virt[i].revents & POLLOUT) {
					FD_SET(fd, writefds);
					ret_value++;
				}
				if (selectio->fds_virt[i].revents & POLLPRI) {
					FD_SET(fd, exceptfds);
					ret_value++;
				}
			}
    }
  }
	vu_poke_arg(readfdsaddr, readfds, sizeof(fd_set), VU_NOT_NESTED);
	vu_poke_arg(writefdsaddr, writefds, sizeof(fd_set), VU_NOT_NESTED);
	vu_poke_arg(exceptfdsaddr, exceptfds, sizeof(fd_set), VU_NOT_NESTED);
  if (orig_ret_value == -1 && selectio->select_rv == -1)
    sd->ret_value = -1;
  else {
		if (orig_ret_value < 0)
			orig_ret_value = 0;
    sd->ret_value = orig_ret_value + ret_value;
	}
	vu_free_arg(readfds, VU_NOT_NESTED);
	vu_free_arg(writefds, VU_NOT_NESTED);
	vu_free_arg(exceptfds, VU_NOT_NESTED);
	xfree(selectio->fds_virt);
  xfree(selectio);
}
