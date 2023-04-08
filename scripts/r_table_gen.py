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

print(
'''#ifndef R_TABLE_H
#define R_TABLE_H

/* THIS FILE HAS BEEN AUTOMATICALLY GENERATED, DO NOT EDIT */

#include <unistd.h>
#include <sys/syscall.h>

extern long (*native_syscall)();
''')

for f in sorted(syscall_names):
	print(f'#define r_{f}(...) native_syscall(__NR_{f}, ## __VA_ARGS__)')

print(
'''
#include <r_table_compat.h>
#include <syscall_nr_compat.h>

#endif''');

