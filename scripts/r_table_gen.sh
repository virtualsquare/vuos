#!/bin/sh

echo "#include<sys/syscall.h>" | gcc -dN -E - | $1/r_table_gen.py
