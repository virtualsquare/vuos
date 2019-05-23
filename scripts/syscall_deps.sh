#!/bin/sh

echo "#include<sys/syscall.h>" | gcc -M -E - | \
			 python3 -c 'import sys,re; print (";".join([re.sub("^(-:  | )","",re.sub(" \\\$","",line[:-1])) for line in sys.stdin]))'

