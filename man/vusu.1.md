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

`vusu` -- set the default networking stack

# SYNOPSIS

`vusu` [*options*] [-] [*user* [*argment...]]

# DESCRIPTION

`vusu` allows one to run commands with a substitute user and group ID (in VUOS).
It requires a module loaded in VUOS able to redefine uid/gid, e.g. `unrealuidgid`.

When called without arguments, `vusu` defaults to running an interactive shell as
(virtual) *root*.

For compatibility with `su`(1), `vusu` defaults to not change the current
directory and to only set the environment variables `HOME` and `SHELL` (plus
`USER` and `LOGNAME` if the target user is not root).  It is recommended to
always use  the  `--login` option (instead of its shortcut -) to avoid side
effects caused by mixing environments.

# OPTIONS
  `-c` *command*, `--command` *command*
: Pass command to the shell with the `-c` option.

  `-`, `-l`, `--login`
: Start the shell as a login shell with an environment similar to a real login:\

  ` `
: \- clears all the environment variables except `TERM`\

  ` `
: \- initializes the environment variables `HOME`, `SHELL`, `USER`, `LOGNAME`, and `PATH`\

  ` `
: \- changes to the target user's home directory\

  ` `
: \- sets argv[0] of the shell to '-' in order to make the shell a login shell

   `-m`, `-p`, `--preserve-environment`
: Preserve  the  entire environment, i.e. it does not set `HOME`, `SHELL`, `USER` nor `LOGNAME`.
: This option is ignored if the option `--login` is specified.

   `-s` *shell*, `--shell` *shell*
: Run the specified shell instead of the default.  The shell to run  is  selected  according  to  the  following
: rules, in order:

  ` `
: \- the shell specified with `--shell`\

  ` `
: \- the shell specified in the environment variable `SHELL`, if the `--preserve-environment` option is used\

  ` `
: \- the shell listed in the passwd entry of the target user\

  ` `
: \- /bin/sh

  `-h`, `--help`
: Display a short help message and exit.

# SEE ALSO
umvu(1), su(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
(most of this man page is a derivative work from `su`(1) man page)
