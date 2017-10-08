#include <signal.h>
#include <sys/epoll.h>

#include <r_table.h>
#include <service.h>
#include <vu_fd_table.h>
#include <syscall_defs.h>

int vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	int epfd = r_epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event event = {.events = events, .data.ptr = private};
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_ADD, sfd, &event);
	if (ret_value < 0) {
		r_close(epfd);
		epfd = -1;
	}
	return epfd;
}

int vu_slowcall_during(int epfd) {
	struct epoll_event useless;
	sigset_t sm;
  sigemptyset(&sm);
	return r_epoll_pwait(epfd, &useless, 1, -1, &sm);
}

int vu_slowcall_out(int epfd, struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
  int sfd = vu_fd_get_sfd(fd, &private, nested);
	struct epoll_event event = {.events = events, .data.ptr = private};
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_DEL, sfd, &event);
	r_close(epfd);
	return ret_value;
}
