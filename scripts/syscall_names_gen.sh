#!/bin/sh

echo "#include<sys/syscall.h>" | gcc -dD -E - | $1/syscall_names_gen.py
