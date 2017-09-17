#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <syscall_defs.h>
#include <syscall_table.h>
#include <vu_execute.h>
#include <epoch.h>
#include <hashtable.h>
#include <arch_table.h>
#include <path_utils.h>
#include <syscall_names.h>
#include <unistd.h>
#include <sys/syscall.h> 
#include <r_table.h>
#include <vu_log.h>
#include <vu_execute.h>
#include <xcommon.h>
#ifdef TESTS
#include <poll.h>
#include <signal.h>
#endif

struct vuht_entry_t *choice_NULL(struct syscall_descriptor_t *sd) {
#ifdef TESTS
	char *path = getsyspath(sd);
	if (path != NULL) {
		printf("%s ", syscallname(sd->syscall_number));
		printf("PATH %s\n", path);
		free(path);
	}
#endif
	return NULL;
}

void wi_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
#if 0
	if (sd->syscall_number == __NR_open)
		sd->action = DOIT_CB_AFTER;
#endif
}

void wd_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
#if 0
	int tid = syscall(__NR_gettid);
	printf("DURING %d\n",tid);
	sigset_t sm;
	sigemptyset(&sm);
	ppoll(NULL, 0, NULL, &sm);
	printf("%d:\n",tid);
	perror("PPOLL");
#endif
}

void wo_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}

void vw_NULL(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
}

struct vuht_entry_t *vchoice_NULL(struct syscall_descriptor_t *sd) {
	return NULL;
}

static inline struct syscall_extra_t *set_extra(struct syscall_descriptor_t *sd,
		char *(*getpath)(struct syscall_descriptor_t *sd, struct vu_stat *buf)) {
	static __thread struct syscall_extra_t extra;
	extra.statbuf.st_mode = 0;
	extra.path = getpath(sd, &extra.statbuf);
	extra.path_errno = errno;
	extra.nested = VU_NOT_NESTED;
	extra.epoch = get_vepoch();
	return &extra;
}

static inline void execute_cleanup (struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht != NULL)
		vuht_drop(ht);
	xfree(sd->extra->path);
}

void vu_syscall_execute(syscall_state_t state, struct syscall_descriptor_t *sd) {
	static __thread struct vuht_entry_t *ht;

	update_vepoch();
	if (sd->syscall_number >= 0) {
		int sysno = vu_arch_table[sd->orig_syscall_number];
		struct syscall_tab_entry *tab_entry = &vu_syscall_table[sysno];
		switch (state) {
			case IN_SYSCALL:
				sd->extra = set_extra(sd, get_syspath);
				printkdebug(s, "IN %d (%d) %s %s", umvu_gettid(), native_syscall(__NR_gettid), 
						syscallname(sd->syscall_number), sd->extra->path);
				ht = tab_entry->choicef(sd);
				if (sd->action == SKIP)
					execute_cleanup(ht,sd);
				else {
					tab_entry->wrapinf(ht, sd);
					if (sd->action != DOIT_CB_AFTER)
						execute_cleanup(ht,sd);
				}
				break;
			case DURING_SYSCALL:
				printkdebug(s, "DURING %d %s %s", umvu_gettid(), 
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapduringf(ht, sd);
				if (sd->action != DOIT_CB_AFTER)
					execute_cleanup(ht,sd);
				break;
			case OUT_SYSCALL:
				printkdebug(s, "OUT %d %s %s", umvu_gettid(), 
						syscallname(sd->syscall_number), sd->extra->path);
				tab_entry->wrapoutf(ht, sd);
				execute_cleanup(ht,sd);
				break;
		}
	} else {
		int vsysno = - sd->syscall_number;
		sd->ret_value = -ENOSYS;
		if (vsysno < VVU_NR_SYSCALLS) {
			struct vsyscall_tab_entry *tab_entry = &vvu_syscall_table[vsysno];
			sd->extra = set_extra(sd, get_vsyspath);
			ht = tab_entry->choicef(sd);
			tab_entry->wrapf(ht, sd);
		}
		sd->action = SKIP;
	}
}

__attribute__((constructor)) 
	static void init(void) {
		debug_set_name(s, "SYSCALL");
	}
