#!/usr/bin/env python3
import sys
import os

syscall_names = []
for line in sys.stdin:
	fields = line.split()
	if len(fields) == 3 and fields[0] == '#define':
		name = fields[1]
		if name[:5] == '__NR_':
			syscall_names.insert(0, name[5:])

print('''#include<sys/syscall.h>
#include<stddef.h>
struct syscallname {
  int sysno;
  char *syscall_name;
  struct syscallname *next;
};

static struct syscallname syscallname_table[] = {''')
for name in syscall_names:
  print(f'''#ifdef __NR_{name}
			{{__NR_{name}, "{name}", NULL}},
#endif''')
print('};')
print('''
#define SYSCALLNAME_TABLE_LEN (sizeof(syscallname_table) / sizeof(*syscallname_table))
#define SYSCALLNAME_HASHMASK 255
static struct syscallname *syscall_name_hash[SYSCALLNAME_HASHMASK + 1];

const char *syscallname(int sysno) {
	int key = sysno & SYSCALLNAME_HASHMASK;
	struct syscallname *scan;
	for (scan = syscall_name_hash[key]; scan != NULL; scan = scan->next)
		if (sysno == scan->sysno)
			return scan->syscall_name;
	return "unknown";
}

__attribute__((constructor))
	static void init (void) {
		unsigned int i;
		for (i = 0; i < SYSCALLNAME_TABLE_LEN; i++) {
			int key = syscallname_table[i].sysno & SYSCALLNAME_HASHMASK;
			syscallname_table[i].next = syscall_name_hash[key];
			syscall_name_hash[key] = &syscallname_table[i];
		}
}''')
