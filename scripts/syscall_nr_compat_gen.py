#!/usr/bin/env python3
import sys
import os

'''
generate fake __NR_xxxx constants for syscalls not defined in the current arch
so that code like:
  if (... == __NR_xxxx)
or
  switch (...) {
		case __NR_xxxx
is just skipped. No arch #ifdef are required.
'''
__NR__first = 1000000000

if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
	print("{}: the input should be 'vu_syscalls.conf'".format(sys.argv[0]))
	sys.exit(1)

# Parse and output

def acceptable(string):
  if string.startswith('#') or \
    string.startswith('-') or \
    string.startswith('null') or \
    string.startswith('BUILTIN'):
    return False
  else:
    return True

def get_syscall_names(string):
  syscall_list = []
  s = string.rpartition(':')
  if ':' == s[1]:
    seq = s[0].split(', ')
    for syscall in seq:
      parts = syscall.rpartition('/')
      if parts[1] == '/':
        syscall_list.append(parts[0])
      else:
        syscall_list.append(parts[2])
  return syscall_list

syscall_list = []
with open(sys.argv[1]) as f:
  for line in f:
    if acceptable(line):
      syscall_list += get_syscall_names(line)

print('''#ifndef __SYSCALL_NR_COMPAT_H
#define __SYSCALL_NR_COMPAT_H

/* Generate compat __NR for missing system calls */

''')

for syscall_nr,syscall_def in enumerate(syscall_list, start = __NR__first):
  print(f'''#ifndef __NR_{syscall_def}
# define __NR_{syscall_def}  {syscall_nr}
#endif\n''')

print(f'#define __NR__first {__NR__first}')
print(f'#define __NR__last {__NR__first + len(syscall_list) - 1}')
print('#define __NR__is_unsupp(X) ((X) >= __NR__first && (X) <= __NR__last)');
print('\n\n#endif')

