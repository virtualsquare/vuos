#include <stdlib.h>
#include <vu_inheritance.h>
#include <vumodule.h>
#include <vu_log.h>
#include <pthread.h>
#include <xcommon.h>

struct mod_inheritance_elem_t {
  mod_inheritance_upcall_t upcall;
  struct mod_inheritance_elem_t *next;
};

static pthread_rwlock_t mod_inheritance_upcall_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct mod_inheritance_elem_t *mod_inheritance_upcall_list_h = NULL;
static int mod_inheritance_upcall_list_count;

static __thread struct mod_inheritance_exec_arg mod_exec_arg = {-1, -1};

/* setuid/setgid are passed to modules:
	 mod_exec_arg is an arg of MOD_INH_EXEC */
void vu_exec_setuid(uid_t uid) {
  mod_exec_arg.exec_uid = uid;
}

void vu_exec_setgid(gid_t gid) {
  mod_exec_arg.exec_gid = gid;
}

void mod_inheritance_upcall_register(mod_inheritance_upcall_t upcall) {
	struct mod_inheritance_elem_t **scan;
	pthread_rwlock_wrlock(&mod_inheritance_upcall_rwlock);
	for (scan = &mod_inheritance_upcall_list_h; *scan != NULL;
			scan = &((*scan) -> next))
		;
	*scan = malloc(sizeof(struct mod_inheritance_elem_t));
	fatal(*scan);
	(*scan)->upcall = upcall;
	(*scan)->next = NULL;
	mod_inheritance_upcall_list_count++;
	pthread_rwlock_unlock(&mod_inheritance_upcall_rwlock);
}

void mod_inheritance_upcall_deregister(mod_inheritance_upcall_t upcall) {
	struct mod_inheritance_elem_t **scan;
	pthread_rwlock_wrlock(&mod_inheritance_upcall_rwlock);
	for (scan = &mod_inheritance_upcall_list_h; *scan != NULL;
			scan = &((*scan) -> next)) {
		struct mod_inheritance_elem_t *this = *scan;
		if (this->upcall == upcall) {
			*scan = this->next;
			mod_inheritance_upcall_list_count--;
			xfree(this);
			break;
		}
	}
	pthread_rwlock_unlock(&mod_inheritance_upcall_rwlock);
}

static void mod_inheritance_call(mod_inheritance_state_t state, void **destination, void *source) {
  struct mod_inheritance_elem_t *scan;
  for (scan = mod_inheritance_upcall_list_h; scan != NULL; scan = scan->next) {
    char *upcallarg = (source != NULL) ? source :
      ((destination != NULL) ? *destination : NULL);
    void *result = scan->upcall(state, upcallarg);
    if (destination != NULL)
      *(destination++) = result;
  }
}

static void *vu_mod_inh_tracer_upcall(inheritance_state_t state, void *arg) {
  void *ret_value = NULL;
	void **args;
	/* CLONE/START protection against mod_inheritance_upcall_list_count modifications:
		 INH_CLONE uses "passing le baton" and keeps the RDLOCK pending until INH_START */
	switch (state) {
		case INH_CLONE:
			pthread_rwlock_rdlock(&mod_inheritance_upcall_rwlock);
			if (mod_inheritance_upcall_list_count > 0) {
				args = malloc(mod_inheritance_upcall_list_count * sizeof(void *));
				fatal(args);
				mod_inheritance_call(MOD_INH_CLONE, args, arg);
				ret_value = args;
			}
			break;
		case INH_START:
			if (mod_inheritance_upcall_list_count > 0) {
				args = (void **) arg;
				mod_inheritance_call(MOD_INH_START, args, NULL);
				xfree(args);
			}
			pthread_rwlock_unlock(&mod_inheritance_upcall_rwlock);
			break;
		case INH_EXEC:
			pthread_rwlock_rdlock(&mod_inheritance_upcall_rwlock);
			if (mod_inheritance_upcall_list_count > 0) {
				mod_inheritance_call(MOD_INH_EXEC, NULL, &mod_exec_arg);
				mod_exec_arg.exec_uid = -1;
				mod_exec_arg.exec_gid = -1;
			}
			pthread_rwlock_unlock(&mod_inheritance_upcall_rwlock);
			break;
		case INH_TERMINATE:
			pthread_rwlock_rdlock(&mod_inheritance_upcall_rwlock);
			if (mod_inheritance_upcall_list_count > 0)
				mod_inheritance_call(MOD_INH_TERMINATE, NULL, NULL);
			pthread_rwlock_unlock(&mod_inheritance_upcall_rwlock);
			break;
		default:
			break;
	}
	return ret_value;
}

__attribute__((constructor))
	static void init(void) {
		vu_inheritance_upcall_register(vu_mod_inh_tracer_upcall);
	}
