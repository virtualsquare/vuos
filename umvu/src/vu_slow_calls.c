#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>

#include <r_table.h>
#include <service.h>
#include <vu_fd_table.h>
#include <syscall_defs.h>
#include <umvu_peekpoke.h>
#include <vu_slow_calls.h>

#define SIZEOF_SIGSET (_NSIG / 8)

int vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	int epfd = r_epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event event = {.events = events, .data.fd = fd};
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_ADD, sfd, &event);
	printk("vu_slowcall_in... %d (add %d)\n", epfd, ret_value);
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

struct slow_thread_arg {
	int epfd;
	pthread_t tid;
};

static void *slow_thread(void *arg) {
	struct slow_thread_arg *slow_arg = arg;
	int epfd = slow_arg->epfd;
	pthread_t tid = slow_arg->tid;
	free(arg);
	struct epoll_event useless;
	printk("vu_slowcall_during... %d\n", epfd);
	int ret_value = r_epoll_wait(epfd, &useless, 1, -1);
	printk("vu_slowcall_wakeup %d %d %lu\n", ret_value, errno, tid);
	////ret_value = r_ptrace(PTRACE_INTERRUPT, tid, 0L, 0);
	////printf("sent PTRACE_INTERRUPT %d\n", ret_value);
	//pthread_kill(tid, SIGCHLD);
	//perror("what?");
	////umvu_unblock
	return NULL;
}	

pthread_t vu_slowcall_during(int epfd) {
	pthread_t newthread;
  pthread_attr_t thread_attr;
	struct slow_thread_arg *arg = malloc(sizeof(struct slow_thread_arg));
	arg->epfd = epfd;
	arg->tid = pthread_self();
	printf(">>>>>>>>>%lu\n", arg->tid);

	/*
	pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&newthread, &thread_attr, &slow_thread, arg);
  pthread_attr_destroy(&thread_attr);
	*/
	if (r_fork() == 0) {
		slow_thread(arg);
		r_exit(0);
	}
	//printk(">>>>>>>>> NEW %d\n", newthread);
	return newthread;
}

#if 0
int vu_slowcall_during(int epfd) {
	int ret_value;
	struct epoll_event useless;
	printk("vu_slowcall_during... %d\n", epfd);
	ret_value = r_epoll_wait(epfd, &useless, 1, -1);
	printk("vu_slowcall_wakeup %d %d\n", ret_value, errno);
	return ret_value;
}
#endif

int vu_slowcall_out(int epfd, pthread_t slowtid, struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
  int sfd = vu_fd_get_sfd(fd, &private, nested);
	pthread_cancel(slowtid);
	struct epoll_event event = {.events = events, .data.fd = fd};
	printk("vu_slowcall_wakeup...\n");
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_DEL, sfd, &event);
	r_close(epfd);
	return ret_value;
}
