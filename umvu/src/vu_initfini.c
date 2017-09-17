#include <stdio.h>
#include <stdlib.h>
#include <vu_log.h>
#include <vu_initfini.h>
#include <signal.h>
#include <r_table.h>

struct voidfun_elem_t {
  voidfun_t upcall;
  struct voidfun_elem_t *next;
};

static struct voidfun_elem_t *constructor_list_h = NULL;
static struct voidfun_elem_t *destructor_list_h = NULL;

static void umvu_voidfun_list_add(struct voidfun_elem_t **listp, voidfun_t upcall) {
  struct voidfun_elem_t **scan;
  for (scan = listp; *scan != NULL; scan = &((*scan) -> next))
    ;
  *scan = malloc(sizeof(struct voidfun_elem_t));
  fatal(*scan);
  (*scan)->upcall = upcall;
  (*scan)->next = NULL;
}

void vu_constructor_register(voidfun_t upcall) {
  umvu_voidfun_list_add(&constructor_list_h, upcall);
}

void vu_destructor_register(voidfun_t upcall) {
  umvu_voidfun_list_add(&destructor_list_h, upcall);
}

static void umvu_voidfun_list_run(struct voidfun_elem_t *list) {
  struct voidfun_elem_t *scan;
  for (scan = list; scan != NULL; scan = scan->next)
    scan->upcall();
}

static void sig_handler(int sig) {
	signal(sig, SIG_DFL);
	vu_fini();
	if (sig == SIGTERM)
    r_exit(0);
  else
    r_kill(-getpgrp(), sig);
}

static void setsighandlers(void) {
	struct sigaction sa = {
    .sa_handler = sig_handler,
    .sa_flags = 0,
    .sa_restorer = NULL};
  sigfillset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGPOLL, SIG_IGN);
	signal(SIGPROF, SIG_IGN);
	signal(SIGVTALRM, SIG_IGN);
}

void vu_init(void) {
	setsighandlers();
	umvu_voidfun_list_run(constructor_list_h);
}

void vu_fini(void) {
	umvu_voidfun_list_run(destructor_list_h);
}
