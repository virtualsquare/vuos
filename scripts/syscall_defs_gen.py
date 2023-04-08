#!/usr/bin/env python3
import sys
import os.path

if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
	print(f"{sys.argv[0]}: the input should be 'vu_syscalls.conf'")
	sys.exit(1)

# Parse and output

code = '''#ifndef __VU_SYSCALL_DEFS__
#define __VU_SYSCALL_DEFS__

/* Arch independent definitions */

'''
vu_syscall_max_namelen = 0
vvu_syscall_max_namelen = 0

with open(sys.argv[1]) as f:
	counter = 0
	vcounter = 1
	mcounter = 0
	for line in f:
		line = line.strip()
		if line == "BUILTIN":
			mcounter = counter
		elif not line.startswith('#'):
			syscall_line = line.split(':')
			if len(syscall_line) > 1:
				syscall = syscall_line[0].strip()
				if len(syscall) > 1:
					syscall = syscall.split(',')[0].strip()
				syscall = syscall.split('/')[0]
				if syscall.startswith('-'):
					syscall = syscall[1:].strip()
					syscall_len = len(syscall)
					if syscall_len > vvu_syscall_max_namelen:
							vvu_syscall_max_namelen = syscall_len
					code += f"#define __VVU_{syscall} {-vcounter}\n"
					vcounter += 1
				else:
					syscall_len = len(syscall)
					if syscall_len > vu_syscall_max_namelen:
							vu_syscall_max_namelen = syscall_len
					code += f"#define __VU_{syscall} {counter}\n"
					counter += 1
if mcounter == 0:
	mcounter = counter
code += f"\n#define VU_NR_SYSCALLS {counter}"
code += f"\n#define VU_NR_MODULE_SYSCALLS {mcounter}"
code += f"\n#define VVU_NR_SYSCALLS {vcounter}"
code += f"\n#define VU_SYSCALL_MAX_NAMELEN {vu_syscall_max_namelen}"
code += f"\n#define VVU_SYSCALL_MAX_NAMELEN {vvu_syscall_max_namelen}"
code += "\n\n#endif"
print(code)
