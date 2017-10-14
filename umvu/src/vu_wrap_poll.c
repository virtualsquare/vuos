#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
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
#define ERESTARTNOHAND 514
#define ERESTART_RESTARTBLOCK 516

static int always_ready_fd;

void wi_epoll_create1(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wo_epoll_create1(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wi_epoll_ctl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wi_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wd_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

void wo_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

struct poll_inout {
	int nfds;
	int nvirt;
	struct pollfd *fds;
	int epfd;
	int fd[];
};

/* poll ppoll */
void wi_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		uintptr_t fdsaddr =  sd->syscall_args[0];
		int nfds = sd->syscall_args[1];
		struct pollfd *fds;
		int nvirt;
		int i;
		vu_alloc_peek_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), nested);
		int virtfd[nfds];
		for (i = nvirt = 0; i < nfds; i++) {
			int fd = fds[i].fd;
			struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
			if (ht) {
				int j;
				for (j = 0; j < nvirt; j++) {
					if (fd == virtfd[j])
						break;
				}
				if (j == nvirt)
					virtfd[nvirt++] = fd;
			}
		}
		if (nvirt == 0) {
			vu_free_arg(fds, nested);
		} else {
			struct poll_inout *pollio = malloc(sizeof(struct poll_inout) + nvirt *sizeof(int));
			struct pollfd *fds_real = malloc(nfds * sizeof(struct pollfd));
			pollio->nfds = nfds;
			pollio->nvirt = nvirt;
			pollio->fds = fds;
			pollio->epfd = r_epoll_create1(EPOLL_CLOEXEC);
			for (i = 0; i < nvirt; i++) {
				int fd = virtfd[i];
				struct vuht_entry_t *ht = vu_fd_get_ht(fd, nested);
				void *private;
				int sfd = vu_fd_get_sfd(fd, &private, nested);
				struct epoll_event event = {.events = 0, .data.fd = fd};
				int j;
				for (j = 0; j < nfds; j++) {
					if (fd == fds[j].fd)
						event.events |= fds[j].events;
				}
				//printk("EPOLL ADD %d %d\n", fd, event.events);
				if (service_syscall(ht, __VU_epoll_ctl)(pollio->epfd, EPOLL_CTL_ADD, sfd, &event) < 0)
					pollio->fd[i] = -1;
				else
					pollio->fd[i] = virtfd[i];
			}
			for (i = 0; i < nfds; i++) {
				int fd = fds[i].fd;
				int j;
				for (j = 0; j < nvirt; j++) {
					if (fd == virtfd[j])
						break;
				}
				if (fd < 0 || j == nvirt) {
					fds_real[i].fd = fds[i].fd;
					fds_real[i].events = fds[i].events;
					fds_real[i].revents = fds[i].revents;
				} else {
					fds_real[i].fd = -1;
					fds_real[i].events = fds_real[i].revents = 0;
				}
			}
			sd->action = DOIT_CB_AFTER;
      sd->inout = pollio;
			vu_poke_arg(fdsaddr, fds_real, nfds * sizeof(struct pollfd), nested);
		}
	}
}

static void poll_thread(int epfd) {
  //struct epoll_event useless;
  struct pollfd pfd = {epfd, POLLIN, 0};
  //printk("poll_thread... %d\n", epfd);
  //int ret_value =
  r_poll(&pfd, 1, -1);
  //printk("poll_thread %d %d\n", ret_value, errno);
}

void wd_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  struct poll_inout *selectio = sd->inout;
  if ((sd->waiting_pid = r_fork()) == 0) {
    poll_thread(selectio->epfd);
    r_exit(1);
  }
}

void wo_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct poll_inout *pollio = sd->inout;
	uintptr_t fdsaddr =  sd->syscall_args[0];
	int nfds = sd->syscall_args[1];
	struct pollfd *fds;
	struct epoll_event eventv[pollio->nvirt];
	int nepoll;
	int orig_ret_value = sd->orig_ret_value;
	int i;
	vu_alloc_peek_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd < 0) {
			fds[i].fd = pollio->fds[i].fd;
			fds[i].events = pollio->fds[i].events;
			fds[i].revents = 0;
		}
	}
	if (sd->waiting_pid != 0) {
		sd->ret_value = orig_ret_value;
	} else {
		int ret_value = 0;
		nepoll = r_epoll_wait(pollio->epfd, eventv, pollio->nvirt, 0);
		for (i = 0; i < nepoll; i++) {
			int fd = eventv[i].data.fd;
			uint32_t events = eventv[i].events;
			int j;
			for (j = 0; j < nfds; j++) {
				if (fd == fds[j].fd) {
					uint32_t fdevents = events & fds[j].events;
					if (fdevents) 
						fds[j].revents |= fdevents;
				}
			}
		}
		for (i = ret_value = 0; i < nfds; i++) {
			if (fds[i].revents)
				ret_value++;
		}
		if (orig_ret_value == -EINTR || orig_ret_value == -ERESTART_RESTARTBLOCK)
			sd->ret_value = ret_value;
		else if (orig_ret_value < 0)
			sd->ret_value = orig_ret_value;
		else
			sd->ret_value = ret_value;
	}
	//printk("orig_ret_value %d ret_value %d -> %d\n", orig_ret_value, ret_value, sd->ret_value );
	vu_poke_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	for (i = 0; i < pollio->nvirt; i++) {
		int fd = pollio->fd[i];
		if (fd >= 0) {
			struct vuht_entry_t *fd_ht = vu_fd_get_ht(fd, VU_NOT_NESTED);
			void *private = NULL;
			int sfd = vu_fd_get_sfd(fd, &private, VU_NOT_NESTED);
			struct epoll_event event = {.events = 0, .data.fd = fd};
			service_syscall(fd_ht, __VU_epoll_ctl)(pollio->epfd, EPOLL_CTL_DEL, sfd, &event);
		}
	}
	r_close(pollio->epfd);
  xfree(pollio->fds);
  xfree(pollio);
}

#define FD_SET_SIZE(nfds) ((__FD_ELT(nfds) + 1) * sizeof(__fd_mask))
struct select_inout {
	int epfd;
	int nfds;
	int fd[];
};

/* select pselect */
void wi_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (!nested) {
		int nfds = sd->syscall_args[0];
		int fd;
		int nvirt;
		uintptr_t readfdsaddr = sd->syscall_args[1];
		uintptr_t writefdsaddr = sd->syscall_args[2];
		uintptr_t exceptfdsaddr = sd->syscall_args[3];
		fd_set readfds, writefds, exceptfds;
		/* get the fd sets from the user-space */
		if (readfdsaddr != 0) {
			vu_peek_arg(readfdsaddr, &readfds, FD_SET_SIZE(nfds), nested);
		} else
			FD_ZERO(&readfds);
		if (writefdsaddr != 0) {
			vu_peek_arg(writefdsaddr, &writefds, FD_SET_SIZE(nfds), nested);
		} else
			FD_ZERO(&writefds);
		if (exceptfdsaddr != 0) {
			vu_peek_arg(exceptfdsaddr, &exceptfds, FD_SET_SIZE(nfds), nested);
		} else
			FD_ZERO(&exceptfds);
		/* count how many virtual fds belong to the fdsets */
		for (fd = nvirt = 0; fd < nfds; fd++) {
			if ((FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds) || FD_ISSET(fd, &exceptfds))
					&& vu_fd_get_ht(fd, nested) != NULL)
				nvirt++;
		}
		/* if there is at least one (otherwise let the process run the real system call) */
		if (nvirt != 0) {
			struct select_inout *selectio = malloc(sizeof(struct select_inout) + nvirt*sizeof(int));
			fatal(selectio);
			selectio->epfd = r_epoll_create1(EPOLL_CLOEXEC);
			for (fd = selectio->nfds = 0; fd < nfds && selectio->nfds < nvirt; fd++) {
				struct vuht_entry_t *fd_ht;
				uint32_t events = (FD_ISSET(fd, &readfds) ? EPOLLIN : 0) |
					(FD_ISSET(fd, &writefds) ? EPOLLOUT : 0) |
					(FD_ISSET(fd, &exceptfds) ? EPOLLPRI : 0);
				if (events != 0 && (fd_ht = vu_fd_get_ht(fd, nested)) != NULL) {
					void *private = NULL;
					int sfd = vu_fd_get_sfd(fd, &private, nested);
					struct epoll_event event = {.events = events, .data.fd = fd};
					//printk("EPOLL ADD %d %d\n", fd, events);
					if (service_syscall(fd_ht, __VU_epoll_ctl)(selectio->epfd, EPOLL_CTL_ADD, sfd, &event) < 0) {
						event.data.fd = -1;
						r_epoll_ctl(selectio->epfd, EPOLL_CTL_ADD, always_ready_fd, &event);
					} else {
						FD_CLR(fd, &readfds);
						FD_CLR(fd, &writefds);
						FD_CLR(fd, &exceptfds);
					}
					selectio->fd[selectio->nfds] = fd;
					selectio->nfds++;
				}
			}
			sd->action = DOIT_CB_AFTER;
			sd->inout = selectio;
			if (readfdsaddr)
				vu_poke_arg(readfdsaddr, &readfds, FD_SET_SIZE(nfds), nested);
			if (writefdsaddr)
				vu_poke_arg(writefdsaddr, &writefds, FD_SET_SIZE(nfds), nested);
			if (exceptfdsaddr)
				vu_poke_arg(exceptfdsaddr, &exceptfds, FD_SET_SIZE(nfds), nested);
		}
	}
}

static void select_thread(int epfd) {
	//struct epoll_event useless;
	struct pollfd pfd = {epfd, POLLIN, 0};
	//printk("select_thread... %d\n", epfd);
	//int ret_value =
	r_poll(&pfd, 1, -1);
	//printk("select_thread %d %d\n", ret_value, errno);
}


void wd_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct select_inout *selectio = sd->inout;
	if ((sd->waiting_pid = r_fork()) == 0) {
		select_thread(selectio->epfd);
		r_exit(1);
	}
}

void wo_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int i;
	int nfds = sd->syscall_args[0];
	uintptr_t readfdsaddr = sd->syscall_args[1];
	uintptr_t writefdsaddr = sd->syscall_args[2];
	uintptr_t exceptfdsaddr = sd->syscall_args[3];
	fd_set readfds, writefds, exceptfds;
	struct select_inout *selectio = sd->inout;
	int orig_ret_value = sd->orig_ret_value;
	int ret_value;
	//printk("select wp %d\n",sd->waiting_pid);
	if (sd->waiting_pid != 0) {
		/*
		if (orig_ret_value == -ERESTARTNOHAND) {
			sd->ret_value = -EINTR;
			sd->action = DO_IT_AGAIN;
		} else */
			sd->ret_value = orig_ret_value;
	} else
	{
		struct epoll_event eventv[selectio->nfds];
		int nepoll;
		ret_value = 0;
		if (readfdsaddr) {
			vu_peek_arg(readfdsaddr, &readfds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
		} else
			FD_ZERO(&readfds);
		if (writefdsaddr) {
			vu_peek_arg(writefdsaddr, &writefds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
		} else
			FD_ZERO(&writefds);
		if (exceptfdsaddr) {
			vu_peek_arg(exceptfdsaddr, &exceptfds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
		} else
			FD_ZERO(&exceptfds);
		if (orig_ret_value < 0) {
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			FD_ZERO(&exceptfds);
		}
		nepoll = r_epoll_wait(selectio->epfd, eventv, selectio->nfds, 0);
		for (i = 0; i < nepoll; i++) {
			int fd = eventv[i].data.fd;
			uint32_t events = eventv[i].events;
			//printk("Got event %d %d\n", fd, events);
			if (fd >= 0) {
				if (events & EPOLLIN) {
					FD_SET(fd, &readfds);
					ret_value++;
				}
				if (events & EPOLLOUT) {
					FD_SET(fd, &writefds);
					ret_value++;
				}
				if (events & EPOLLPRI) {
					FD_SET(fd, &exceptfds);
					ret_value++;
				}
			}
		}
		if (orig_ret_value == -EINTR || orig_ret_value == -ERESTARTNOHAND)
			sd->ret_value = ret_value;
		else if (orig_ret_value < 0) 
			sd->ret_value = orig_ret_value;
		else
			sd->ret_value = orig_ret_value + ret_value;
		if (readfdsaddr)
			vu_poke_arg(readfdsaddr, &readfds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
		if (writefdsaddr)
			vu_poke_arg(writefdsaddr, &writefds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
		if (exceptfdsaddr)
			vu_poke_arg(exceptfdsaddr, &exceptfds, FD_SET_SIZE(nfds), VU_NOT_NESTED);
	}
	for (i = 0; i < selectio->nfds; i++) {
		int fd = selectio->fd[i];
		if (fd >= 0) {
			struct vuht_entry_t *fd_ht = vu_fd_get_ht(fd, VU_NOT_NESTED);
			void *private = NULL;
			int sfd = vu_fd_get_sfd(fd, &private, VU_NOT_NESTED);
			struct epoll_event event = {.events = 0, .data.fd = fd};
			service_syscall(fd_ht, __VU_epoll_ctl)(selectio->epfd, EPOLL_CTL_DEL, sfd, &event);
		}
	}
	//printk("WO select ret_value = %d %d\n", orig_ret_value, sd->ret_value);
	r_close(selectio->epfd);
	xfree(selectio);
}

__attribute__((constructor))
	static void init (void) {
		always_ready_fd = eventfd(1, EFD_CLOEXEC);
	}
