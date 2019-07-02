#ifndef _VU_THREAD_SD_H
#define _VU_THREAD_SD_H

/* get/set the syscall_descriptor of the current thread,
	 mainly for modules */

/* set the new value of thread_sd and return the previous,
   so that it can be used later to restore the old value */
struct syscall_descriptor_t *set_thread_sd(struct syscall_descriptor_t *sd);
/* get the current thread_sd */
struct syscall_descriptor_t *get_thread_sd(void);

#endif

