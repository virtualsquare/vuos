#!/usr/bin/env python3
import sys
import os

syscall_names = {}
for line in sys.stdin:
	fields = line.split()
	if len(fields) == 3 and fields[0] == '#define':
		name, value = fields[1:3]
		if name[:5] == '__NR_':
			syscall_names[int(value)] = name[5:]

print('''#define UNKNOWN_SYSTEM_CALL "unknown"

static char *syscallname_table[] = {''')
if syscall_names:
	nmax = max(syscall_names.keys())
	for i in range(nmax + 1):
		if i in syscall_names:
			print(f'\t"{syscall_names[i]}",')
		else:
			print('UNKNOWN_SYSTEM_CALL,')
else:
			print('UNKNOWN_SYSTEM_CALL,')
print('''};

#define SYSCALL_NAME_TABLE_SIZE (sizeof(syscallname_table)/sizeof(*syscallname_table))
char *syscallname(int sysno) {
  if (sysno >= 0 && sysno < (int) SYSCALL_NAME_TABLE_SIZE)
    return syscallname_table[sysno];
  else
    return UNKNOWN_SYSTEM_CALL;
}''')
