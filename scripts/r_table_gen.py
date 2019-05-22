#!/usr/bin/env python3
import sys
import os

syscall_names = []
for line in sys.stdin:
	fields = line.split()
	if len(fields) == 2 and fields[0] == '#define':
		name = fields[1]
		if name[:5] == '__NR_':
			syscall_names.append(name[5:])

print('''#ifndef R_TABLE_H
#define R_TABLE_H

/* THIS FILE HAS BEEN AUTOMATICALLY GENERATED, DO NOT EDIT */

#include <unistd.h>
#include <sys/syscall.h>

extern long (*native_syscall)();
''')

for f in sorted(syscall_names):
	print('#define r_{}(...) native_syscall(__NR_{}, ## __VA_ARGS__)'.format(f, f))

print('''#endif''');

