<!--
.\" Copyright (C) 2023 VirtualSquare. Project Leader: Renzo Davoli
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
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->

# NAME

fusereal, vufusereal - mount a file system tree to another place using FUSE and vufuse

# SYNOPSIS

`fusereal` [`-hVdfs`] [`-o` _options_ ] *olddir* *newdir*

in a `umvu` session:

`mount -t vufusereal` [`-o` _options_ ] *olddir* *newdir*

# DESCRIPTION

`fusereal` 
causes the contents of *olddir* to be accessible (also) under *newdir*.

`vufusereal` is the VUOS/vufuse submodule of `fusereal`

# OPTIONS

`fusereal` is build upon FUSE (Filesystem in Userspace) library.
the  complete  set  of available options depends upon the specific
FUSE installed.  Execute `fusereal -h` to retrieve the actual complete
list.

### general options

  `-o` opt,[opt...]
: FUSE and file specific mount options.

  `-h`
: display a usage and options summary

  `-V` &nbsp; `--version`
: display version

### main FUSE mount options

  These options are not valid in VUOS/vufuse.

  `-d` &nbsp; `-o debug`
: enable debug output (implies -f)

  `-f`
: foreground operation

  `-s`
: disable multi-threaded operation

# SEE ALSO
`fuse`(8), `umvu`(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.

