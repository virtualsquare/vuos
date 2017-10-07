#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <umvu_tracer.h>
#include <r_table.h>
#include <ptrace_defs.h>
#include <xcommon.h>
#include <vu_log.h>
#include <umvu_peekpoke.h>

static int umvu_trace(pid_t tracee_tid);
static void default_syscall_handler(syscall_state_t state, struct syscall_descriptor_t *sd);
static syscall_handler_t syscall_handler = default_syscall_handler;

static void default_syscall_handler(syscall_state_t state, struct syscall_descriptor_t *sd) {
#if 0
	printf("trace %d - SCNO %d\n", state, sd->syscall_number);
	sd->action = DOIT_CB_AFTER;
	if (state == OUT_SYSCALL) 
		sd->ret_value = sd->orig_ret_value;
#endif
}

struct inheritance_elem_t {
	inheritance_upcall_t upcall;
	struct inheritance_elem_t *next;
};

static struct inheritance_elem_t *inheritance_upcall_list_h = NULL;
static int inheritance_upcall_list_count;

void umvu_inheritance_upcall_register(inheritance_upcall_t upcall) {
	struct inheritance_elem_t **scan;
 for (scan = &inheritance_upcall_list_h; *scan != NULL;
		 scan = &((*scan) -> next))
	 ;
 *scan = malloc(sizeof(struct inheritance_elem_t));
 fatal(*scan);
 (*scan)->upcall = upcall;
 (*scan)->next = NULL;
 inheritance_upcall_list_count++;
}

static void umvu_inheritance_call(inheritance_state_t state, void **destination, void *source) {
	struct inheritance_elem_t *scan;
	for (scan = inheritance_upcall_list_h; scan != NULL; scan = scan->next) {
		char *upcallarg = (source != NULL) ? source :
			((destination != NULL) ? *destination : NULL);
		void *result = scan->upcall(state, upcallarg);
		if (destination != NULL)
			*(destination++) = result;
	}
}

/* struct definitions */
typedef struct tracer_args {
	pid_t tracee_tid;
	struct user_regs_struct regs;
	void *inherited_args[];
} tracer_args;

static void unblock_tracee(pid_t tid, struct user_regs_struct *regs)
{
	P_INTERRUPT(tid, 0L);
	r_wait4(tid, NULL, __WALL, NULL);
	P_SETREGS(tid, regs);
	P_SYSCALL(tid, 0L);
}

static void *spawn_tracer(void *arg)
{
	tracer_args *t_arg = (tracer_args *)arg;
	pid_t tracee_tid = t_arg->tracee_tid;
	umvu_settid(tracee_tid);
	umvu_inheritance_call(INH_START, t_arg->inherited_args, NULL);

	P_SEIZE_NODIE(tracee_tid, PTRACE_STD_OPTS);
	unblock_tracee(tracee_tid, &(t_arg->regs));
	free(t_arg);
	umvu_trace(tracee_tid);
	pthread_exit(NULL);
	return NULL;
}

static void block_tracee(pid_t tid, struct user_regs_struct *regs)
{
	struct syscall_descriptor_t sys_orig, sys_modified;
	P_GETREGS_NODIE(tid, regs);
	umvu_peek_syscall(regs, &sys_orig, IN_SYSCALL);
	sys_modified = sys_orig;
	/* change syscall to poll(NULL, 0, -1); */
	sys_modified.syscall_number = __NR_poll;
	sys_modified.syscall_args[0] = 0;
	sys_modified.syscall_args[1] = 0;
	sys_modified.syscall_args[2] = -1;
	umvu_poke_syscall(regs, &sys_modified, IN_SYSCALL);
	P_SETREGS_NODIE(tid, regs);
	sys_orig.prog_counter -= SYSCALL_INSTRUCTION_LEN;
	umvu_poke_syscall(regs, &sys_orig, IN_SYSCALL);
}

static void transfer_tracee(pid_t newtid, syscall_arg_t clone_flags)
{
	pthread_t newthread;
	pthread_attr_t thread_attr;
	tracer_args *t_args = (tracer_args *)
		malloc(sizeof(tracer_args) + inheritance_upcall_list_count * sizeof(void *));
	struct user_regs_struct *regs;

	fatal(t_args);
	regs = &(t_args->regs);
	block_tracee(newtid, regs);
	/*init args for new thread*/
	t_args->tracee_tid = newtid;
	umvu_inheritance_call(INH_CLONE, t_args->inherited_args, &clone_flags);
	P_DETACH_NODIE(newtid, 0L);
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&newthread, &thread_attr, &spawn_tracer, t_args);
	pthread_attr_destroy(&thread_attr);
}

static int umvu_trace(pid_t tracee_tid)
{
	int wstatus, sig_tid;
	syscall_state_t syscall_state = IN_SYSCALL;
	struct user_regs_struct regs;
	struct syscall_descriptor_t syscall_desc;
	syscall_arg_t clone_flags;
	//printf("new thread for %d\n", tracee_tid);
	while (1) {
		sig_tid = r_wait4(-1, &wstatus, __WALL | __WNOTHREAD, NULL);
		if (sig_tid == -1) {
			umvu_inheritance_call(INH_TERMINATE, NULL, NULL);
			return -1;
		} else if (WIFSTOPPED(wstatus)) {
			if (WSTOPSIG(wstatus) == SIGTRAP) {
				if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
					/* tracee is about to exit */
					unsigned long exit_status;
					P_GETEVENTMSG(sig_tid, &exit_status);
					P_DETACH(sig_tid, 0L);
					umvu_inheritance_call(INH_TERMINATE, NULL, NULL);
					return exit_status;
				} else if (wstatus >> 8 ==
						(SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
					/* the tracee is doing execve() */
					/* if a thread which is not the thread group leader performs
					 * an execve() his tid become equal to the thread group leader,
					 * we must update tracee_tid otherwise a execve could be mistaken for
					 * a clone() */
					tracee_tid = sig_tid;
					umvu_inheritance_call(INH_EXEC, NULL, NULL);
					//printf("exec %d\n", tracee_tid);
				}
				else if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
						wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
						wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
					/* the tracee is doing a clone */
					clone_flags = syscall_desc.syscall_args[0];
				}
				P_SYSCALL(sig_tid, 0L);
			} else if (sig_tid != tracee_tid) {
				/*new tracee*/
				if (wstatus >> 16 == PTRACE_EVENT_STOP) {
					P_SYSCALL_NODIE(sig_tid, 0L);
				} else {
					transfer_tracee(sig_tid, clone_flags);
				}
			} else if (WSTOPSIG(wstatus) == (SIGTRAP | 0x80)) {
				/*SYSCALL*/
				if (syscall_state == IN_SYSCALL) {
					syscall_desc.action = DOIT;
					P_GETREGS(sig_tid, &regs);
					umvu_peek_syscall(&regs, &syscall_desc, syscall_state);
					syscall_handler(syscall_state, &syscall_desc);
					if (syscall_desc.action == BLOCKIT) {
						struct syscall_descriptor_t sys_modified = syscall_desc;
						umvu_block(&sys_modified);
						umvu_poke_syscall(&regs, &sys_modified, syscall_state);
						P_SETREGS(sig_tid, &regs);
						syscall_desc.action = DOIT_CB_AFTER;
					} else {
						if (syscall_desc.action == SKIPIT)
							syscall_desc.syscall_number = __NR_getpid;
						if (umvu_poke_syscall(&regs, &syscall_desc, syscall_state))
							P_SETREGS(sig_tid, &regs);
					}
					P_SYSCALL(sig_tid, 0L);
					if (syscall_desc.action == DOIT_CB_AFTER) {
						syscall_state = DURING_SYSCALL;
						syscall_handler(syscall_state, &syscall_desc);
					}
					syscall_state = OUT_SYSCALL;
				} else {
					if (syscall_desc.action != DOIT) {
						P_GETREGS(sig_tid, &regs);
						umvu_peek_syscall(&regs, &syscall_desc, syscall_state);
						if (syscall_desc.action == DOIT_CB_AFTER)
							syscall_handler(syscall_state, &syscall_desc);
						if (umvu_poke_syscall(&regs, &syscall_desc, syscall_state))
							P_SETREGS(sig_tid, &regs);
					}
					syscall_state = IN_SYSCALL;
					P_SYSCALL(sig_tid, 0L);
				}
			} else {
				/*group-stop or signal injection*/
				P_SYSCALL(sig_tid, WSTOPSIG(wstatus));
			}
		}
	}
}

int umvu_tracepid(pid_t childpid, syscall_handler_t syscall_handler_arg) {
	int wstatus;
	P_SEIZE(childpid, PTRACE_STD_OPTS);
	P_SYSCALL(childpid, 0L);
	if (syscall_handler_arg != NULL)
		syscall_handler = syscall_handler_arg;
	umvu_settid(childpid);
	wstatus = umvu_trace(childpid);
	return wstatus;
}

int umvu_tracer_fork(void) {
	pid_t childpid;

	if (!(childpid = r_fork())) {
		/*child*/
		raise(SIGSTOP);
		return 0;
	} else {
		/*parent*/
		r_wait4(-1, NULL, WUNTRACED, NULL);

		return childpid;
	}
}

/* an empty handler is needed to get EINTR */

static void handler(int signum, siginfo_t *info, void *useless) {
#if 0
	int tid = syscall(__NR_gettid);
	printf("HANDLER signum %d %d\n",signum,tid);
#endif
}

__attribute__((constructor))
	static void init (void) {
		struct sigaction sa;
		sigset_t chld_set;
		sa.sa_flags = SA_RESTART;
		sa.sa_sigaction = handler;
		sigfillset(&sa.sa_mask);
		sa.sa_restorer = NULL;
		sigaction(SIGCHLD, &sa, NULL);
		sigemptyset(&chld_set);
		sigaddset(&chld_set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &chld_set, NULL);
	}
