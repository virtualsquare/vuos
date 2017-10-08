#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>

#include <r_table.h>
#include <service.h>
#include <vu_fd_table.h>
#include <syscall_defs.h>

#define SIZEOF_SIGSET (_NSIG / 8)

int vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	int epfd = r_epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event event = {.events = events, .data.fd = fd};
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_ADD, sfd, &event);
	printk("vu_slowcall_in... %d (add %d)\n", epfd, ret_value);
	//sigset_t sm;
  //sigemptyset(&sm);
	//int rv=  r_epoll_pwait(epfd, &event, 1, -1, &sm, SIZEOF_SIGSET);
	//printk("test %d %d\n", rv, errno);
	if (ret_value < 0) {
		r_close(epfd);
		epfd = -1;
	}
	return epfd;
}

void printsigpending(void) {
  sigset_t set;
  sigpending(&set);
  int i;
	int tid = syscall(__NR_gettid);
  for (i = 1; i < _NSIG; i++) {
		if (sigismember(&set, i))
				printk("PENDING %d %d\n",i,tid);
	}
}

int vu_slowcall_during(int epfd) {
	int ret_value;
	struct epoll_event useless;
	//printsigpending();
	//sigset_t sm;
  //sigemptyset(&sm);
	printk("vu_slowcall_during... %d\n", epfd);
	//ret_value = r_epoll_pwait(epfd, &useless, 1, -1, &sm, SIZEOF_SIGSET);
	ret_value = r_epoll_wait(epfd, &useless, 1, -1);
	printk("vu_slowcall_wakeup %d %d\n", ret_value, errno);
	return ret_value;
}

int vu_slowcall_out(int epfd, struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
  int sfd = vu_fd_get_sfd(fd, &private, nested);
	struct epoll_event event = {.events = events, .data.fd = fd};
	printk("vu_slowcall_wakeup...\n");
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_DEL, sfd, &event);
	r_close(epfd);
	return ret_value;
}
