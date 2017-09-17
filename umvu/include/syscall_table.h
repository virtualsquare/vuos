#ifndef _SYSCALL_TABLE_H_
#define _SYSCALL_TABLE_H_
struct syscall_descriptor_t;
struct vuht_entry_t;

typedef struct vuht_entry_t *choicef_t(struct syscall_descriptor_t *);
typedef void wrapf_t(struct vuht_entry_t *, struct syscall_descriptor_t *);

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
extern char *vu_syscall_names[];
extern char *vvu_syscall_names[];
#endif
