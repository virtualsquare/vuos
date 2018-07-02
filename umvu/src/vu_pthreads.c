#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>
#include <vu_log.h>
#include <vu_inheritance.h>

static int (*libc_pthread_create)();

struct _pthread_arg {
  void *(*start_routine) (void *);
  void *start_arg;
	void *inherited_args[];
};

void cleanup(void *arg) {
	//printk("cleanup \n");
	vu_inheritance_call(INH_PTHREAD_TERMINATE, NULL, NULL);
}

void *_pthread_wrapper(void *arg) {
  struct _pthread_arg *ptarg = arg;

  void *(*start_routine) (void *) = ptarg->start_routine;
  void *start_arg = ptarg->start_arg;

	vu_inheritance_call(INH_PTHREAD_START, ptarg->inherited_args, NULL);
	free(ptarg);
  pthread_cleanup_push(cleanup, NULL);
	//printk("start_routine \n");
  start_arg = start_routine(start_arg);
	//printk("start_routine DONE\n");
  pthread_cleanup_pop(1);

  return start_arg;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg) {
	//printk("pthread_create\n");
	struct _pthread_arg *ptarg = malloc(sizeof(struct _pthread_arg) + vu_inheritance_inout_size());
	fatal(ptarg);
	ptarg->start_routine = start_routine;
  ptarg->start_arg = arg;

	vu_inheritance_call(INH_PTHREAD_CLONE, ptarg->inherited_args, (void *) -1);

  return libc_pthread_create(thread, attr, _pthread_wrapper, ptarg);
}

__attribute__((constructor))
	static void init(void) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		libc_pthread_create = dlsym (RTLD_NEXT, "pthread_create");
#pragma GCC diagnostic pop
	}
