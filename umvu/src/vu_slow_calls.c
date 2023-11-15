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

#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <dlfcn.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>

#include <r_table.h>
#include <service.h>
#include <vu_fd_table.h>
#include <syscall_defs.h>
#include <umvu_peekpoke.h>
#include <vu_slow_calls.h>

#define STACKSIZE 4096

struct slowcall {
	int epfd;
	//char stack[STACKSIZE];
};
static int (*libc_clone)();

int vu_slowcall_test(struct slowcall *sc) {
	struct pollfd pfd = {sc->epfd, POLLIN, 0};
	return poll(&pfd, 1, 0);
}

struct slowcall *vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	if (vu_fd_get_flflags(fd, nested) & O_NONBLOCK)
		return NULL;
	else {
		void *private = NULL;
		int sfd = vu_fd_get_sfd(fd, &private, nested);
		int epfd = r_epoll_create1(EPOLL_CLOEXEC);
		struct epoll_event event = {.events = events, .data.fd = fd};
		int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_ADD, sfd, &event, private);
		//printk("vu_slowcall_in... %d (add %d)\n", epfd, ret_value);
		if (ret_value < 0) {
			r_close(epfd);
			return NULL;
		} else {
			struct slowcall *sc = malloc(sizeof(struct slowcall));
			sc->epfd = epfd;
			return sc;
		}
	}
}

static int slow_thread(void *arg) {
	struct slowcall *sc = arg;
	struct pollfd pfd = {sc->epfd, POLLIN, 0};
	//printk("vu_slowcall_during... %d\n", pfd);
	poll(&pfd, 1, -1);
	//printk("vu_slowcall_wakeup %d %d\n", errno);
	return 0;
}

pid_t vu_slowcall_during(struct slowcall *sc) {
	//printk(">>>>>>>>>%lu\n", pthread_self());
#if 0
	return libc_clone(slow_thread, sc->stack + STACKSIZE,
			CLONE_FILES | CLONE_VM | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD,
			sc);
#endif
	  pid_t pid;
  if ((pid = r_fork()) == 0)
		r_exit(slow_thread(sc));
	return pid;
}

void vu_slowcall_out(struct slowcall *sc, struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	struct epoll_event event = {.events = events, .data.fd = fd};
	//printk("vu_slowcall_wakeup...\n");
	service_syscall(ht, __VU_epoll_ctl)(sc->epfd, EPOLL_CTL_DEL, sfd, &event, private);
	r_close(sc->epfd);
	free(sc);
}

__attribute__((constructor))
	static void init(void) {
		/* init the libc_clone pointer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		libc_clone = dlsym (RTLD_NEXT, "clone");
#pragma GCC diagnostic pop
	}
