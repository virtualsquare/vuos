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

`vuname` -- print system/view information - set view name.

# SYNOPSIS

`vuname` [*options* ...]

or

`vuname` *newname*


# DESCRIPTION

Print certain system/view information.  With no options, and no arguments, same as -s.
With no options and exactly one argument: set the VUOS view name.

This tool extends `uname`(1). It should provide the same output of `uname` except when
it runs as a VUOS process (or if `--x`/`--nouname` disables this feature).
In VUOS the system information is extended with view information.

# OPTIONS

  `-a`, `--all`
: print all information, in the following order, except omit `-p` and `-i` if unknown.

  `-s`, `--kernel-name`
: print the kernel name

  `-n`, `--nodename`
: print the network node hostname

  `-r`, `--kernel-release`
: print the kernel release

  `-v`, `--kernel-version`
: print the kernel version

  `-m`, `--machine`
: print the machine hardware name

  `-p`, `--processor`
: print the processor type or "unknown"

  `-i`, `--hardware-platform`
: print the hardware platform or "unknown"

  `-o`, `--operating-system`
: print the operating system

  `-U`, `--serverid`
: print the VUOS server id (it is the process id of the hypervisor)

  `-V`, `--viewname`
: print the view name

  `-P`, `--prompt`
: return a suitable (shell) command prompt: the nodename (`-n`) if `vuname` runs outside VUOS else the view name (`-V`) if
		it has been defined otherwise the nodename followedby the server id enclosed in square brackets (something like *host[42]*).

  `-x`, `--nouname`
: do  not  use  uname (without this flag the command behaves like uname when it runs on a non VUOS enabled environment).

  `-q`, `--quiet`
: quiet mode: error messages suppressed

  `--help`
: display a help message and exit

  `--version`
: output version information and exit

