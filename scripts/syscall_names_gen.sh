#!/bin/sh

echo "#include<sys/syscall.h>" | $1 -dD -E - | $2/syscall_names_gen.py
