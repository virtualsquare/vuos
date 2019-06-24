#!/bin/sh

# compute and print on stdout all the (nested_ dependencies of "#include<sys/syscall.h>"

echo "#include<sys/syscall.h>" | gcc -M -E - | \
	sed ':a; N; s/\n/ /; ta' | sed 's/^-: *//;s/ *$//;s/\\//g;s/  */;/g'

# sed magics: first sed=join all the lines
# second sed: delete leading -: and trailing spaces, delete all \ and change any sequence of spaces to ;
