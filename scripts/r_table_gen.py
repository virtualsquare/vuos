#!/usr/bin/env python3
import sys
import os

def isman2page(f):
	s = f.split('.2')
	if len(s) < 1:
		return False
	if s[1] == '' or s[1].startswith('.'):
		return True
	return False

mandir = '/usr/share/man/man2'
if len(sys.argv) > 1:
	mandir = sys.argv[1]

print('''#ifndef R_TABLE_H
#define R_TABLE_H

#include <unistd.h>
#include <sys/syscall.h>

extern long (*native_syscall)();
''')

manpages2 = [f.split('.2')[0] for f in os.listdir(mandir) if
	isman2page(f)]

for f in sorted(manpages2):
	print('#define r_{}(...) native_syscall(__NR_{}, ## __VA_ARGS__)'.format(f, f))

print('''#endif''');

