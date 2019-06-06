#!/bin/sh

# compute and prin on stdout all the (nested_ dependencies of "#include<sys/syscall.h>"

echo "#include<sys/syscall.h>" | gcc -M -E - | \
			 python3 -c 'import sys,re; print (";".join([re.sub("^(-:  | )","",re.sub(" \\\$","",line[:-1])) for line in sys.stdin]))'

