#ifndef VU_INHERITANCE_H
#define VU_INHERITANCE_H

/* inheritance management:
	 hypervisor modules can register a callback upcall that will be called
	 in case of the event listed in inheritance_state_t.
	 It is used by core sections (or modules) which need to initialize and maintain
	 thread private data structures. */

/* Warning: vu_inheritance_upcall_register is *NOT* thread safe. It has been designed
	 for __attribute__((constructor)) functions (so the call happens before
	 going multi-threading. A thread safe implementation for modules as
   an upper layer is provided by vu_mod_inheritance.c */

/* CLONE/START is the pair of events to manage a new process/thread:
	 CLONE is an event of the parent process/creating thread
	 START is the first event if the newborn process/thread.
	 It is possible cor CLONE to pass data to START */

/* INH_CLONE, INH_START, INH_EXEC, INH_TERMINATE report event of user-processes
	 INH_PTHREAD_CLONE, INH_PTHREAD_START, INH_PTHREAD_TERMINATE are about
	 threads of the hypervisor */

typedef enum inheritance_state_t {
	INH_CLONE = 0,
	INH_START = 1,
	INH_EXEC = 2,
	INH_TERMINATE = 3,
	INH_PTHREAD_CLONE = 10,
	INH_PTHREAD_START = 11,
	INH_PTHREAD_TERMINATE = 13
} inheritance_state_t;

typedef void *(*inheritance_upcall_t)(inheritance_state_t state, void *ioarg, void *arg);
/* register an upcall handler */
void vu_inheritance_upcall_register(inheritance_upcall_t upcall);

/*
	 call all the registered handlers.

	 vu_inheritance_call(INH_SOMETHING, NULL, commonarg):
	 >>> all the handlers get commonarg as their arg
	 >>> the return values of the handlers are discarded
	 vu_inheritance_call(INH_SOMETHING, inoutarg, commonarg):
	 >>> all the handlers get commonarg as their arg
	 >>> each handler gets its element in inoutarg as its ioarg.
	 >>> the return value of each handler updates its element in inoutarg.
	 >>> inoutargs must point to a memory area vu_inheritance_inout_size() bytes wide
	 >>> (START / CLONE events use this)
*/

void vu_inheritance_call(inheritance_state_t state, void **inout, void *arg);
size_t vu_inheritance_inout_size(void);

#endif
