/*
 *   VUOS: view OS project
 *   Copyright (C) 2017, 2019 Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <poll.h>

#include <linux_32_64.h>
#include <xstat.h>
#include <xcommon.h>
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

/* epoll table:
 * it stores the list of virtual fds for epoll, poll and select */
struct epoll_tab_elem {
	int fd;
	int wepfd;
  struct vuht_entry_t *ht;
  int sfd;
  void *private;
  struct epoll_event event;
  struct epoll_tab_elem *next;
};

struct epoll_tab {
	struct epoll_tab_elem *head;
};

/* epoll info: this is foe epoll only,
	 the private field of the file table element of an epoll file
	 points to this */
struct epoll_info {
	pthread_mutex_t mutex;
	int nested;
	struct epoll_tab tab;
};

/* management of epoll table */
static struct epoll_tab epoll_tab_init(void) {
	struct epoll_tab ret_value = {NULL};
	return ret_value;
}

static struct epoll_tab_elem *epoll_tab_search(struct epoll_tab tab, int fd) {
  struct epoll_tab_elem *scan;
  for (scan = tab.head; scan != NULL; scan = scan->next) {
    if (scan->fd == fd)
      return scan;
  }
  return NULL;
}

static inline struct epoll_tab_elem *epoll_tab_head(struct epoll_tab tab) {
	return tab.head;
}

static void epoll_tab_del(struct epoll_tab *tab, int fd) {
  struct epoll_tab_elem **scan;
  for (scan = &tab->head; *scan != NULL; scan = &((*scan)->next)) {
    struct epoll_tab_elem *this = *scan;
    if (this->fd == fd) {
      *scan = this->next;
      free(this);
      return;
    }
  }
}

static inline struct epoll_tab_elem *epoll_tab_alloc(void) {
	 struct epoll_tab_elem *new = malloc(sizeof(struct epoll_tab_elem));
  fatal(new);
	return new;
}

static void epoll_tab_add(struct epoll_tab *tab, struct epoll_tab_elem *new) {
  new->next = tab->head;
  tab->head = new;
}

static void epoll_tab_destroy(struct epoll_tab *tab) {
	while (tab->head != NULL) {
		struct epoll_tab_elem *tmp = tab->head;
		tab->head = tmp->next;
		xfree(tmp);
	}
}

/* epoll info management */
static struct epoll_info *epoll_info_create(int nested) {
	struct epoll_info *info = malloc(sizeof(struct epoll_info));
	fatal(info);
	pthread_mutex_init(&info->mutex, NULL);
  info->nested = nested;
  info->tab = epoll_tab_init();
  return info;
}

static void epoll_info_lock(struct epoll_info *info) {
  pthread_mutex_lock(&info->mutex);
}

static void epoll_info_unlock(struct epoll_info *info) {
  pthread_mutex_unlock(&info->mutex);
}

static void epoll_info_destroy(struct epoll_info *info) {
	if (info) {
		epoll_tab_destroy(&info->tab);
		pthread_mutex_destroy(&info->mutex);
		xfree(info);
	}
}

/* common wait code */

static void vu_poll_wait_thread(struct syscall_descriptor_t *sd, int epfd) {
  if ((sd->waiting_pid = r_fork()) == 0) {
    struct pollfd pfd = {epfd, POLLIN, 0};
     //printk("epoll_thread... %d\n", epfd);
		 //int ret_value =
    r_poll(&pfd, 1, -1);
     //printk("epoll_thread %d %d\n", ret_value, errno);
    r_exit(1);
  }
}

/* EPOLL:
 * epoll_create: set up a epollfd (epfd) in the hypervisor, create epoll_info and
 * register the user level file descriptor in the file table.
 * (for non nested only: epoll_create is a real epoll_create for nested virtualization)
 *
 * epoll_ctl/EPOLL_CTL_ADD: if ht != NULL (i.e. if it is a virtual file) create an epollfd (wepfd),
 * call the module's epoll_ctl/EPOLL_CTL_ADD, add wepfd as a file checked by epfd (EPOLLIN).
 * (this indirection is needed as if a user lever fd is duplicated the service file descriptor is the same
 * so it would not be possible to add both file descriptors in the same epoll set
 *
 * epoll_ctl/MOD: call module's epoll_ctl/MOD and update/delete the epoll table.
 *
 * epoll_wait:
 * (for non nested only: epoll_wait is a real epoll_wait for nested virtualization)
 * the hypervisor forks a wait watchdog process waiting on epfl, while the user process
 * is waiting on its epoll.
 * An event on a virtual fd causes the watchdog to terminate, otherwise the user process epoll_wait
 * exits if there is an event on a non-virtualized fd or a timeout.
 * the wo (wrap-out) epoll_wait code merges the events.
 */

void wi_epoll_create1(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->action = DOIT_CB_AFTER;
}

void wo_epoll_create1(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
  int fd = sd->orig_ret_value;
  if (fd >= 0) {
		int syscall_number = sd->syscall_number;
     /* args */
    int flags;
    int epfd;
    struct vu_fnode_t *fnode;
    struct epoll_info *info = epoll_info_create(nested);
    switch (syscall_number) {
      case __NR_epoll_create:
        flags = 0;
        break;
      case __NR_epoll_create1:
        flags = sd->syscall_args[0];
        break;
    }
    epfd = r_epoll_create1(EPOLL_CLOEXEC);
    sd->extra->statbuf.st_mode = (sd->extra->statbuf.st_mode & ~S_IFMT) | S_IFEPOLL;
    sd->extra->statbuf.st_dev = 0;
    sd->extra->statbuf.st_ino = epfd;
		//printk("wo_epoll_create1 %d %d %p\n", fd, epfd, info);
    /* use the file table to map the user level fd to the (real) epollfd for modules */
    fnode = vu_fnode_create(NULL, NULL, &sd->extra->statbuf, 0, epfd, info);
    vu_fd_set_fnode(fd, nested, fnode, (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0);
  }
  sd->ret_value = sd->orig_ret_value;
}

/* epoll_ctl_add/del/mod code is in three specific functions*/
static int epoll_ctl_add(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, int epfd,struct epoll_info *info,
		int sfd, void *private) {
	int nested = sd->extra->nested;
	int fd = sd->syscall_args[2];
	uintptr_t eventaddr = sd->syscall_args[3];
	struct epoll_tab_elem *epoll_elem = epoll_tab_search(info->tab, fd);
	if (epoll_elem != NULL)
		return -EEXIST;
	else {
		int wepfd = r_epoll_create1(EPOLL_CLOEXEC);
		//printk("wi_epoll_ctl ADD %d %p %d\n", fd, info, wepfd);
		if (wepfd < 0)
			return -errno;
		else {
			int retval;
			struct epoll_event *event;
			vu_alloc_peek_local_arg(eventaddr, event, sizeof(event), nested);
			struct epoll_event mod_event = {.events = event->events, .data.u64 = 0};
			retval = service_syscall(ht, __VU_epoll_ctl)(wepfd, EPOLL_CTL_ADD, sfd, &mod_event, private);
			//printk("RETVAL %d %s\n", retval, strerror(errno));
			if (retval < 0) {
				r_close(wepfd);
				return retval;
			} else {
				struct epoll_tab_elem *new = epoll_tab_alloc();
				struct epoll_event welem = {.events = POLLIN, .data.ptr = new};
				new->fd = fd;
				new->wepfd = wepfd;
				new->ht = ht;
				new->sfd = sfd;
				new->private = private;
				new->event = *event;
				epoll_tab_add(&info->tab, new);
				r_epoll_ctl(epfd, EPOLL_CTL_ADD, wepfd, &welem);
			}
			return retval;
		}
	}
}

static int epoll_ctl_mod(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, int epfd, struct epoll_info *info,
		int sfd, void *private) {
	int nested = sd->extra->nested;
	int fd = sd->syscall_args[2];
	uintptr_t eventaddr = sd->syscall_args[3];
	struct epoll_tab_elem *epoll_elem = epoll_tab_search(info->tab, fd);
	if (epoll_elem == NULL)
		return -ENOENT;
	else {
		int retval;
		struct epoll_event *event;
		//printk("wi_epoll_ctl MOD %d %p \n", fd, info);
		vu_alloc_peek_local_arg(eventaddr, event, sizeof(event), nested);
		struct epoll_event mod_event = {.events = event->events, .data.u64 = 0};
		retval = service_syscall(ht, __VU_epoll_ctl)(epoll_elem->wepfd, EPOLL_CTL_MOD, sfd, &mod_event, private);
		if (retval >= 0)
			epoll_elem->event = *event;
		return retval;
	}
}

static int epoll_ctl_del(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, int epfd, struct epoll_info *info,
		int sfd, void *private) {
	int fd = sd->syscall_args[2];
	struct epoll_tab_elem *epoll_elem = epoll_tab_search(info->tab, fd);
	if (epoll_elem == NULL)
		return -ENOENT;
	else {
		int retval;
		//printk("wi_epoll_ctl DEL %d %p \n", fd, info);
		retval = service_syscall(ht, __VU_epoll_ctl)(epoll_elem->wepfd, EPOLL_CTL_DEL, sfd, NULL, private);
		if (retval >= 0) {
			r_close(epoll_elem->wepfd);
			epoll_tab_del(&info->tab, fd);
		}
		return retval;
	}
}

void wi_epoll_ctl(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
    int proc_epfd = sd->syscall_args[0];
    int op = sd->syscall_args[1];
		int fd = sd->syscall_args[2];
		int mode = vu_fd_get_mode(proc_epfd, nested);
		//printk("wi_epoll_ctl %d %p epfd %d, fd %d\n", sd->extra->nested, ht, proc_epfd, fd);
		sd->action = SKIPIT;
		if (nested) {
			uintptr_t eventaddr = sd->syscall_args[3];
			void *private = NULL;
			int sfd = vu_fd_get_sfd(fd, &private, nested);
			struct epoll_event *event;
			vu_alloc_peek_local_arg(eventaddr, event, sizeof(event), nested);
			sd->ret_value = service_syscall(ht, __VU_epoll_ctl)
				(proc_epfd, op, sfd, event, private);
			//printk("NESTED EPOLL %d %d %d -> %d\n", proc_epfd, op, sfd, sd->ret_value);
			return;
		}
		if (mode == 0)
			sd->ret_value = EBADF;
		else if ((mode & S_IFMT) != S_IFEPOLL)
			sd->ret_value = -EINVAL;
		else {
			struct epoll_info *info;
			int epfd = vu_fd_get_sfd(proc_epfd, (void **) &info, nested);
			void *private = NULL;
      int sfd = vu_fd_get_sfd(fd, &private, nested);
			epoll_info_lock(info);
			switch (op) {
				case EPOLL_CTL_ADD:
					sd->ret_value = epoll_ctl_add(ht, sd, epfd, info, sfd, private);
					break;
				case EPOLL_CTL_DEL:
					sd->ret_value = epoll_ctl_del(ht, sd, epfd, info, sfd, private);
					break;
				case EPOLL_CTL_MOD:
					sd->ret_value = epoll_ctl_mod(ht, sd, epfd, info, sfd, private);
					break;
				default:
					sd->ret_value = -EINVAL;
			}
			epoll_info_unlock(info);
		}
	}
}

static int epoll_close_upcall(struct vuht_entry_t *ht, int epfd, void *private) {
  struct epoll_info *info = private;
  epoll_info_lock(info);
	struct epoll_tab_elem *head;

	//printk("epoll_close_upcall %d %p\n", epfd, info);
	while ((head = epoll_tab_head(info->tab)) != NULL) {
		//printk("wi_epoll_ctl DEL %d %p \n", head->fd, info);
		service_syscall(head->ht, __VU_epoll_ctl)(head->wepfd, EPOLL_CTL_DEL, head->sfd, NULL, head->private);
		r_close(head->wepfd);
		epoll_tab_del(&info->tab, head->fd);
	}
  epoll_info_unlock(info);
  epoll_info_destroy(info);
  r_close(epfd);
  return 0;
}

void wi_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int pepfd = sd->syscall_args[0];
	struct epoll_info *info;
  __attribute__((unused)) int epfd = vu_fd_get_sfd(pepfd, (void **) &info, nested);
	//printk("wi_epoll_wait n%d %d %p %p\n", nested, epfd, info, epoll_tab_head(info->tab));
	if (epoll_tab_head(info->tab) != NULL)
		sd->action = DOIT_CB_AFTER;
}

void wd_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int pepfd = sd->syscall_args[0];
  struct epoll_info *info;
  int epfd = vu_fd_get_sfd(pepfd, (void **) &info, VU_NOT_NESTED);
	vu_poll_wait_thread(sd, epfd);
}

void wo_epoll_wait(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int pepfd = sd->syscall_args[0];
  struct epoll_info *info;
  int epfd = vu_fd_get_sfd(pepfd, (void **) &info, nested);
	int orig_ret_value = sd->orig_ret_value;
  /* args */
  uintptr_t eventaddr = sd->syscall_args[1];
  struct epoll_event *events;
  int maxevents = sd->syscall_args[2];
  //printk("wo_epoll_wait %d %d\n", maxevents, orig_ret_value);
	/* there are user events or the watchdog terminated and then the process got a PTRACE_INTERRUPT */
	if(orig_ret_value >= 0 || orig_ret_value == -EINTR) {
		int ret_value = orig_ret_value;
		/* EINTR is not an error, it means that there are virtual events only */
		if (ret_value < 0)
			ret_value = 0;
		/* there are "struct epoll_event" slots available */
		if (maxevents > ret_value) {
			int available_events = maxevents - ret_value;
			int epoll_ret_value;
			int i;
			//printk("available_events %d\n", available_events);
			vu_alloc_peek_arg(eventaddr, events, maxevents * sizeof(struct epoll_event), nested);
			//printk("VU alloc okay\n");
			epoll_ret_value = r_epoll_wait(epfd, events + ret_value, available_events, 0);
			//printk("epoll_ret_value %d\n", epoll_ret_value);
			epoll_info_lock(info);
			/* add the pending events of virtual file descriptors. Each ready-to-read wepfd
				 has exactly one pending event. */
			for (i = ret_value; i < ret_value + epoll_ret_value; i++) {
				struct epoll_tab_elem *elem = events[i].data.ptr;
				if (elem) {
					r_epoll_wait(elem->wepfd, &events[i], sizeof(struct epoll_event), nested);
					events[i].data = elem->event.data;
				}
			}
			epoll_info_unlock(info);
			if (epoll_ret_value > 0) {
        ret_value += epoll_ret_value;
				/* update the struct epoll_event (array) argument */
        vu_poke_arg(eventaddr, events, ret_value * sizeof(struct epoll_event), nested);
        sd->ret_value = ret_value;
      } else
        sd->ret_value = orig_ret_value;
      vu_free_arg(events, nested);
		}
	} else
		sd->ret_value = orig_ret_value;
}

/* management of poll/ppoll */
struct poll_inout {
  int epfd;
  int nvirt;
  struct epoll_tab tab;
	int orig_fd[];
};

/* XXX TBD nested poll for hypervisor's threads */
void wi_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	uintptr_t fdsaddr =  sd->syscall_args[0];
	int nfds = sd->syscall_args[1];
	if (nfds < 0) {
		sd->ret_value = -EINVAL;
		sd->action = SKIPIT;
		return;
	}
  if (!nested) {
		struct pollfd *fds;
		struct epoll_tab tab = epoll_tab_init();
		int i;
		vu_alloc_peek_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), nested);
		for (i = 0; i < nfds; i++) {
			int fd = fds[i].fd;
			struct vuht_entry_t *fd_ht;
			/* if the fd is valid and virtual add it to the epoll table 'tab'*/
			if (fd >= 0 && (fd_ht = vu_fd_get_ht(fd, nested)) != NULL) {
				struct epoll_tab_elem *elem;
				/* merge all the pollfd args referring to the same virtual file descriptor */
				if ((elem = epoll_tab_search(tab, fd)) == NULL) {
					void *private = NULL;
          int sfd = vu_fd_get_sfd(fd, &private, nested);
          elem = epoll_tab_alloc();
          elem->fd = fd;
          elem->wepfd = -1;
          elem->ht = fd_ht;
          elem->sfd = sfd;
          elem->private = private;
          elem->event.events = 0;
          elem->event.data.ptr = elem;
          epoll_tab_add(&tab, elem);
        }
				elem->event.events |= fds[i].events;
			}
		}
		/* if there are virtual file descriptors */
		if (epoll_tab_head(tab) != NULL) {
      struct poll_inout *pollio = malloc(sizeof(struct poll_inout) +
					nfds * sizeof(int));
			struct epoll_tab_elem *scan;
			fatal(pollio);
			/* create an epoll fd */
      pollio->epfd = r_epoll_create1(EPOLL_CLOEXEC);
      pollio->nvirt = 0;
      pollio->tab = tab;
			/* save the original file descriptors */
			for (i = 0; i < nfds; i++) {
				int fd = fds[i].fd;
				if (vu_fd_get_ht(fd, nested) == NULL)
					pollio->orig_fd[i] = -1;
				else {
					pollio->orig_fd[i] = fds[i].fd;
					fds[i].fd = -1;
				}
			}
			/* add to the epoll set all the virtual file descriptors */
			for (scan = epoll_tab_head(tab); scan != NULL; scan = scan->next) {
				pollio->nvirt++;
				//printk("EPOLL_CTL_ADD %d %d %p\n", pollio->epfd, scan->sfd, scan->private);
        service_syscall(scan->ht, __VU_epoll_ctl)
					(pollio->epfd, EPOLL_CTL_ADD, scan->sfd, &scan->event, scan->private); // XXX error mgmt?
      }
			sd->inout = pollio;
      sd->action = DOIT_CB_AFTER;
			/* store the modified struct pollfd array */
      vu_poke_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), nested);
    }
    vu_free_arg(fds, nested);
  }
}

void wd_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  struct poll_inout *pollio = sd->inout;
  vu_poll_wait_thread(sd, pollio->epfd);
}

static inline int poll_add_events(int nfds, struct pollfd *fds, int fd, uint32_t events) {
	int count = 0;
	int i;
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == fd) {
			uint32_t revents = events & fds[i].events;
			if (fds[i].events == 0 && revents != 0)
				count++;
			fds[i].revents |= revents;
		}
	}
	return count;
}

void wo_poll(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct poll_inout *pollio = sd->inout;
  uintptr_t fdsaddr =  sd->syscall_args[0];
  int nfds = sd->syscall_args[1];
  struct pollfd *fds;
  int orig_ret_value = sd->orig_ret_value;
  struct epoll_tab_elem *scan;
  vu_alloc_peek_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	int i;
	/* restore file descriptors */
	for (i = 0; i < nfds; i++) {
		if (pollio->orig_fd[i] >= 0) fds[i].fd = pollio->orig_fd[i];
	}
	/* the user level poll terminated first: evens on real fd only */
	if (sd->waiting_pid != 0)
    sd->ret_value = orig_ret_value;
	else {
		/* EINTR/ERESTARTNOHAND are not error for us, just the watchdog terminated */
		if (orig_ret_value == -EINTR || orig_ret_value == -ERESTARTNOHAND)
			orig_ret_value = 0;
		if (orig_ret_value < 0)
			sd->ret_value = orig_ret_value;
		else {
			/* get nvirtmax events and store revents in the struct pollfd elements */
			struct epoll_event eventv[pollio->nvirt];
			int nepoll;
			nepoll = r_epoll_wait(pollio->epfd, eventv, pollio->nvirt, 0);
			for (i = 0; i < nepoll; i++) {
				scan = eventv[i].data.ptr;
				orig_ret_value += poll_add_events(nfds, fds, scan->fd, eventv[i].events);
			}
    }
		sd->ret_value = orig_ret_value;
  }
	/* de-register the epoll requests for modules */
	for (scan = epoll_tab_head(pollio->tab); scan != NULL; scan = scan->next) {
		service_syscall(scan->ht, __VU_epoll_ctl)(pollio->epfd, EPOLL_CTL_DEL, scan->sfd, NULL, scan->private); // XXX error mgmt?
	}
	epoll_tab_destroy(&pollio->tab);
  r_close(pollio->epfd);
	vu_poke_arg(fdsaddr, fds, nfds * sizeof(struct pollfd), VU_NOT_NESTED);
	vu_free_arg(fds, VU_NOT_NESTED);
  xfree(pollio);
}

/* management of select pselect */

/* select pselect */
#define FD_SET_SIZE(nfds) ((__FD_ELT(nfds) + 1) * sizeof(__fd_mask))
#define EPOLLIN_SET (EPOLLRDNORM | EPOLLRDBAND | EPOLLIN | EPOLLHUP | EPOLLERR) /* Ready for reading */
#define EPOLLOUT_SET (EPOLLWRBAND | EPOLLWRNORM | EPOLLOUT | EPOLLERR) /* Ready for writing */
#define EPOLLEX_SET (EPOLLPRI) /* Exceptional condition */
#define EPOLL_SELECT_SET (EPOLLIN | EPOLLOUT | EPOLLPRI)

struct select_inout {
  int epfd;
	int nvirt;
	struct epoll_tab tab;
};

static inline void peek_fd_set(uintptr_t fdsetaddr, fd_set *fdset, int nfds, int nested) {
	if (fdsetaddr == 0)
		FD_ZERO(fdset);
	else
		vu_peek_arg(fdsetaddr, fdset, FD_SET_SIZE(nfds), nested);
}

static inline void poke_fd_set(uintptr_t fdsetaddr, fd_set *fdset, int nfds, int nested) {
	if (fdsetaddr != 0)
		vu_poke_arg(fdsetaddr, fdset, FD_SET_SIZE(nfds), nested);
}

static inline uint32_t fd_set2events(int fd, fd_set *r, fd_set *w, fd_set *x) {
	uint32_t events = 0;
	if (FD_ISSET(fd, r)) events |= EPOLLIN_SET;
	if (FD_ISSET(fd, w)) events |= EPOLLOUT_SET;
	if (FD_ISSET(fd, x)) events |= EPOLLEX_SET;
	return events;
}

static inline int events2fd_set(int fd, uint32_t events, uint32_t revents, fd_set *r, fd_set *w, fd_set *x) {
	int count = 0;
	if (events & EPOLLIN && revents & EPOLLIN_SET) FD_SET(fd, r), count++;
	if (events & EPOLLOUT && revents & EPOLLOUT_SET) FD_SET(fd, w), count++;
	if (events & EPOLLPRI && revents & EPOLLEX_SET) FD_SET(fd, x), count++;
	return count;
}

static inline void fd_set_fdclr(int fd, fd_set *r, fd_set *w, fd_set *x) {
	FD_CLR(fd, r);
	FD_CLR(fd, w);
	FD_CLR(fd, x);
}

/* XXX TBD nested select for hypervisor's threads */
void wi_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int nfds = sd->syscall_args[0];
	uintptr_t readfdsaddr = sd->syscall_args[1];
	uintptr_t writefdsaddr = sd->syscall_args[2];
	uintptr_t exceptfdsaddr = sd->syscall_args[3];
	if (nfds < 0) {
		sd->ret_value = -EINVAL;
		sd->action = SKIPIT;
		return;
	}
  if (!nested) {
    struct epoll_tab tab = epoll_tab_init();
		int fd;
		fd_set readfds, writefds, exceptfds;
		peek_fd_set(readfdsaddr, &readfds, nfds, nested);
		peek_fd_set(writefdsaddr, &writefds, nfds, nested);
		peek_fd_set(exceptfdsaddr, &exceptfds, nfds, nested);
		/* search for events requested on virtual file descriptors,
			 add virtual file descriptors (with attended events) to the epoll file table 'tab' */
		for (fd = 0; fd < nfds; fd++) {
			uint32_t events = fd_set2events(fd, &readfds, &writefds, &exceptfds);
			if (events != 0) {
				struct vuht_entry_t *fd_ht;
				if ((fd_ht = vu_fd_get_ht(fd, nested)) != NULL) {
					void *private = NULL;
					int sfd = vu_fd_get_sfd(fd, &private, nested);
					struct epoll_tab_elem *new = epoll_tab_alloc();
					struct epoll_event event = {.events = events, .data.ptr = new};
					fd_set_fdclr(fd, &readfds, &writefds, &exceptfds);
					new->fd = fd;
					new->wepfd = -1;
					new->ht = fd_ht;
					new->sfd = sfd;
					new->private = private;
					new->event = event;
					epoll_tab_add(&tab, new);
				}
			}
		}
		/* if select involves virtual file descriptors */
		if (epoll_tab_head(tab) != NULL) {
      struct select_inout *selectio = malloc(sizeof(struct select_inout));
      struct epoll_tab_elem *scan;
      fatal(selectio);
			selectio->epfd = r_epoll_create1(EPOLL_CLOEXEC);
      selectio->nvirt = 0;
      selectio->tab = tab;
			for (scan = epoll_tab_head(tab); scan != NULL; scan = scan->next) {
        selectio->nvirt++;
				//printk("EPOLL_CTL_ADD %d %d %p\n", selectio->epfd,  scan->sfd, scan->private);
				service_syscall(scan->ht, __VU_epoll_ctl)
					(selectio->epfd, EPOLL_CTL_ADD, scan->sfd, &scan->event.events, scan->private); // XXX error mgmt?
      }
			poke_fd_set(readfdsaddr, &readfds, nfds, nested);
			poke_fd_set(writefdsaddr, &writefds, nfds, nested);
			poke_fd_set(exceptfdsaddr, &exceptfds, nfds, nested);
			sd->inout = selectio;
      sd->action = DOIT_CB_AFTER;
		}
	}
}

void wd_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct select_inout *selectio = sd->inout;
  vu_poll_wait_thread(sd, selectio->epfd);
}

void wo_select(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = VU_NOT_NESTED;
	int orig_ret_value = sd->orig_ret_value;
  struct select_inout *selectio = sd->inout;
  struct epoll_tab_elem *scan;
  //printk("wo_select\n");
	if (sd->waiting_pid != 0) // userland select terminated first, no virtual events
		sd->ret_value = orig_ret_value;
	else {
		int nfds = sd->syscall_args[0];
		uintptr_t readfdsaddr = sd->syscall_args[1];
		uintptr_t writefdsaddr = sd->syscall_args[2];
		uintptr_t exceptfdsaddr = sd->syscall_args[3];
		fd_set readfds, writefds, exceptfds;
		if (orig_ret_value == -EINTR || orig_ret_value == -ERESTARTNOHAND) {
			/* interrupted syscall: virtual events only. */
			peek_fd_set(0, &readfds, nfds, nested);
			peek_fd_set(0, &writefds, nfds, nested);
			peek_fd_set(0, &exceptfds, nfds, nested);
			orig_ret_value = 0;
		} else {
			peek_fd_set(readfdsaddr, &readfds, nfds, nested);
			peek_fd_set(writefdsaddr, &writefds, nfds, nested);
			peek_fd_set(exceptfdsaddr, &exceptfds, nfds, nested);
		}
		if (orig_ret_value < 0) {
			/* restore the original fd_sets, as the mannual says:
				 On error, -1 is returned, and errno is set to indicate the  error;  the file descriptor sets are unmodified */
			for (scan = epoll_tab_head(selectio->tab); scan != NULL; scan = scan->next)
				events2fd_set(scan->fd, scan->event.events, EPOLL_SELECT_SET, &readfds, &writefds, &exceptfds);
			sd->ret_value = orig_ret_value;
    } else {
			struct epoll_event events[selectio->nvirt];
			int epollnfds, i;
			int ret_value = 0;
			epollnfds = r_epoll_wait(selectio->epfd, events, selectio->nvirt, 0);
			//printk("wo_select here n%d %d\n", epollnfds);
			for (i = 0; i < epollnfds; i++) {
				struct epoll_tab_elem *elem = events[i].data.ptr;
				//printk("wo_select elem %p %d\n", elem, elem->fd);
				if (elem)
					ret_value += events2fd_set(elem->fd, elem->event.events, events[i].events, &readfds, &writefds, &exceptfds);
				sd->ret_value = orig_ret_value + ret_value;
				//printk("wo_select final %d %d+%d\n", sd->ret_value, orig_ret_value, ret_value);
			}
		}
		poke_fd_set(readfdsaddr, &readfds, nfds, nested);
		poke_fd_set(writefdsaddr, &writefds, nfds, nested);
		poke_fd_set(exceptfdsaddr, &exceptfds, nfds, nested);
	}
	/* de-register the epoll requests for modules */
	for (scan = epoll_tab_head(selectio->tab); scan != NULL; scan = scan->next)
		service_syscall(scan->ht, __VU_epoll_ctl)(selectio->epfd, EPOLL_CTL_DEL, scan->sfd, NULL, scan->private); // XXX error mgmt?
	epoll_tab_destroy(&selectio->tab);
	r_close(selectio->epfd);
	xfree(selectio);
}

__attribute__((constructor))
	static void init (void) {
		vu_fnode_set_close_upcall(S_IFEPOLL, epoll_close_upcall);
	}
