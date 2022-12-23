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

`vumount` -- mount a filesystem or a resource

# SYNOPSIS

`vumount` [*options* ...] *source* *destination*

# DESCRIPTION

Everything is (or can be seen) as a file. It is part of the philosophy
of UNIX.  The file hierarchy is the global naming facility.

VUOS follows this principle: VUOS modules use `mount`(2) not only to
mount virtual filesystems but also to activate other virual services.
The mountpoint, *destination* in the synopsis, is the name
that will be used to identify the virtual entity/service.

For example, in `vudev` it is possible to mount devices, in `vunet` the
mountpoint is the name of the networking stack, `vustack`(1) uses the path
ofthe mountpoint to set the current stack for processes.

`vumount` is just a command interface to `mount`(2).
The `mount`(8) command is a complex tool which includes several features like
the management of /etc/fstab and /etc/mtab. `mount`(8) is a
root setuid executable and performs security checks before the actual
`mount`(2) syscall request. `mount`(8) can be used in VUOS
in place of `vumount` but it requires the (virtual) real uid of the
executing process to be 0 (root). e.g. `vusu`(1) can be used to
set the virtual real uid to 0.
`vumount` has been designed for VUOS but can be used to run the `mount`
system call directly, without all the other management actions provided by
`mount`(8). `vumount` is not setuid root.

# OPTIONS

  `-h`, `--help`
: Print a short help message and exit.

  `-o` *list*, `--options` *list*
: comma-separated list of mount options

  `-t` *fstype*, `--types` *fstype*
: define the filesystem type

  `-r`, `--read-only`
: mount the filesystem read-only (same as -o ro)

  `-w`, `--rw`, `--read-write`
: mount the filesystem read-write (default)

  `-B`, `--bind`
: mount a subtree somewhere else (same as -o bind)

  `-M`, `--move`
: move a subtree to some other place

  `-R`, `--rbind`
: mount a subtree and all submounts somewhere else

# SEE ALSO
umvu(1), vu_insmod(1), vu_lsmod(1), vu_rmmod(1), vuumount(1), vudebug(1)

# AUTHOR

VirtualSquare. Project leader: Renzo Davoli
