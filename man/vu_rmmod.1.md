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

`vu_rmmod` -- user-mode implementation of VUOS

# SYNOPSIS

`vu_rmmod` [*options* ...] *vu_module* [*vu_module*]

# DESCRIPTION

*This is a VUOS command. It works only inside a vuos virtual namespace* see `umvu`(1).

This command removes one or more modules currently loaded in umvu.

# OPTIONS

  `-h`, `--help`
: Print a short help message and exit.

# EXAMPLE

  The following command removes vudev (virtual devices) and vunet (virtual networking).

```
vu_rmmod vudev vunet
```

# SEE ALSO
umvu(1), vu_insmod(1), vu_lsmod(1)

# AUTHOR

VirtualSquare. Project leader: Renzo Davoli

