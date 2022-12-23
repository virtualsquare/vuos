<!--
.\" Copyright (C) 2019 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

`vuumount` -- unmount a filesystem or a resource

# SYNOPSIS

`vuumount` [*options* ...] *source* *destination*

# DESCRIPTION

`vuumount` is just a command interface to `umount`(2).
It has been designed for VUOS but can be used to run the `umount`
system call directly, without all the other management actions provided by 
`umount`(8). `vuumount` is not setuid root (viceversa `umount` is setuid root).

# OPTIONS

  `-h`, `--help`
: Print a short help message and exit.

  `-f`, `--force`
: force unmount (e.g. in case of an unreachable NFS system)

  `-d`, `--detach-loop`
: if mounted loop device, also free this loop device
	

# SEE ALSO
umvu(1), vu_insmod(1), vu_lsmod(1), vu_rmmod(1), vumount(1), udebug(1)

# AUTHOR

VirtualSquare. Project leader: Renzo Davoli
