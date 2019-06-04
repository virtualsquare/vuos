#ifndef _SYSCALL_TABLE_H_
#define _SYSCALL_TABLE_H_
/* header file for the file syscall_table.c which is automatically generated
   during the building/compilation process. The source file to generate
   arch_table.c is vu_syscall.conf */

struct syscall_descriptor_t;
struct vuht_entry_t;

/* a choice function processes the actual arguments of a system call request
	 and returns the pointer to the hash table entry which is responsible to handle
	 the request. When a choice function returns NULL it means that the request
	 is not to be virtualized, so it is forwarded to the kernel */
typedef struct vuht_entry_t *choicef_t(struct syscall_descriptor_t *);
typedef void wrapf_t(struct vuht_entry_t *, struct syscall_descriptor_t *);

/* vu_syscall_table defines for each _VU_ system call:
	 the choice function,
	 the system call pre-processing wrapper
	   it is evaluated before the kernel gets the system call.
	 the system call co-processing wrapper
	   it is evaluated while the kernel is processing the request
	 the system call post-processing wrapper
	  it runs when the kernel has completed the system call request
 */

struct syscall_tab_entry{
	choicef_t *choicef;
	wrapf_t *wrapinf;
	wrapf_t *wrapduringf;
	wrapf_t *wrapoutf;
};

struct vsyscall_tab_entry{
	choicef_t *choicef;
	wrapf_t *wrapf;
};

extern struct syscall_tab_entry vu_syscall_table[];
extern struct vsyscall_tab_entry vvu_syscall_table[];

/* these arrays provide the names of _VU_ system calls (for debugging purposes) */
extern char *vu_syscall_names[];
extern char *vvu_syscall_names[];
#endif
