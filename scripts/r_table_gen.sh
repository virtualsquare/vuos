#!/bin/sh

echo "#include<sys/syscall.h>" | $1 -dN -E - | $2/r_table_gen.py
