#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <r_table.h>
#include <service.h>
#include <vu_fd_table.h>
#include <vu_initfini.h>
#include <syscall_defs.h>

#define SIZEOF_SIGSET (_NSIG / 8)

void sigchld_add(int tid, int efd);

int vu_slowcall_in(struct vuht_entry_t *ht, int fd, uint32_t events, int nested) {
	void *private = NULL;
	int sfd = vu_fd_get_sfd(fd, &private, nested);
	int epfd = r_epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event event = {.events = events, .data.fd = fd};
	int efd = r_eventfd(0, EFD_CLOEXEC);
	struct epoll_event efdevent = {.events = EPOLLIN, .data.fd = efd};
	r_epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &efdevent);
	int ret_value = service_syscall(ht, __VU_epoll_ctl)(epfd, EPOLL_CTL_ADD, sfd, &event);
	sigchld_add(umvu_gettid(), efd);
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
	umvu_unblock();
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


/* an empty handler is needed to get EINTR */

pthread_mutex_t sigchld_thread_terminate = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sigchld_thread_check = PTHREAD_MUTEX_INITIALIZER;

struct sigchld {
	long efd;
	long tid;
	struct sigchld *next;
};
struct sigchld *sigchld_head = NULL;

void sigchld_add(int tid, int efd) {
	struct sigchld *new = malloc(sizeof(struct sigchld));
	new->tid = tid;
	new->efd = efd;
	printk("sigchld_add %d %d\n",new->tid,new->efd);
	pthread_mutex_lock(&sigchld_thread_check);
	new->next = sigchld_head;
	sigchld_head = new;
	pthread_mutex_unlock(&sigchld_thread_check);
}

static void handler(int signum, siginfo_t *info, void *useless) {
#if 0
  int tid2 = syscall(__NR_gettid);
  printf("HANDLER signum %d %d (%d)\n",signum,tid2,info->si_pid);
#endif
	int tid = info->si_pid;
	struct sigchld **scan;
	pthread_mutex_lock(&sigchld_thread_check);
	for (scan = &sigchld_head; *scan != NULL; scan = &((*scan)->next)) {
		struct sigchld *this = *scan;
		//printk("%d=======\n",this->tid);
		if (this->tid == tid) {
			uint64_t one = 1;
			printk("FOUND %d %d\n", this->tid, this->efd);
			write(this->efd, &one, sizeof(one));
			*scan = this->next;
			free(this);
			break;
		}
	}
	pthread_mutex_unlock(&sigchld_thread_check);

}

static void *sigchld_thread(void *arg) {
	struct sigaction sa;
	sigset_t chld_set;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sa.sa_sigaction = handler;
	sigfillset(&sa.sa_mask);
	sa.sa_restorer = NULL;
	sigaction(SIGCHLD, &sa, NULL);
	sigemptyset(&chld_set);
	sigaddset(&chld_set, SIGCHLD);
	pthread_sigmask(SIG_UNBLOCK, &chld_set, NULL);
	pthread_mutex_lock(&sigchld_thread_terminate);
	pthread_mutex_unlock(&sigchld_thread_terminate);
	return NULL;
}

void sigchld_thread_fini(void) {
	pthread_mutex_unlock(&sigchld_thread_terminate);
}

__attribute__((constructor))
	static void init (void) {
		sigset_t chld_set;
		sigemptyset(&chld_set);
		sigaddset(&chld_set, SIGCHLD);
		pthread_mutex_lock(&sigchld_thread_terminate);
		pthread_sigmask(SIG_BLOCK, &chld_set, NULL);
		pthread_t newthread;
		pthread_attr_t thread_attr;
		pthread_attr_init(&thread_attr);
		pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&newthread, &thread_attr, &sigchld_thread, NULL);
		pthread_attr_destroy(&thread_attr);
		vu_destructor_register(sigchld_thread_fini);
	}

