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

`vudebug` -- debug utility for umvu

# SYNOPSIS

`vudebug` --help

`vudebug` [*debarg* [*debarg* ...]] [ -- *command* [*args*]]

where *debarg* has the following syntax:

`+`[*tag*[*tag* ...]][`:`*colorspec*]

or

`-`[*tag*[*tag* ...]]

or

`?`[*tag*[*tag* ...]]

and *colorspec* is a combination of the following characters: `nwrgbcmyNWRGBCMY+-_*#`

# DESCRIPTION

vudebug enables or disables debug log messages. Log messages are
classified into categories. Each category is identified by a *tag*
(one alphanumeric character). By convention lowercase letters are for
logging messages of the hypervisor, while capital letters are for modules.

When `vudebug` command line ends with `--` followed by a command and its
command line arguments, logging is enabled for the execution of that command
(and for all the subprocesses it eventually creates). Otherwise `vudebug`
changes the categories to log globally, for all the processes.

# OPTIONS

  `--help`
: Print a short help message and exit.

  *debarg*
: each debug argument begins by `+`, `-` or `?` followed by zero, one or more
: debug tags. (`+` enables log messages, `-` disables log messages, `?` check if the
:     log messages are enabled). When the debug argument has no tags, it is applied to all
: the tags.
: Log messages of different categories can be shown in different colors and font effects.
: When `vudebug` is used to enable/re-enable tags (`+`) each *debarg* can be followed by a
: semicolon (`:`) and a color specification. A color specification is a string composed by the
: following characters:

  ` `
: `n w r g b c m y`: set foreground color (black, white, red, green, blue, cyan, magenta or yellow)

  ` `
: `N W R G B C M Y`: set background color (black, white, red, green, blue, cyan, magenta or yellow)

  ` `
: `+ - _ * #`: font effect (bright, dim,underlined, blinking, reverse video).

# EXAMPLES

Get a list of available logging categories:

```
$ vudebug ?
D -   VUDEV
F -   VUFUSE
N -   VUNET
a -   ACTION
c -   CHOICE
f -   FILETABLE
m -   MODULE
n -   NESTED
p -   PATH
s -   SYSCALL
v -   VNODE
```

the list may vary depending on the version of the hypervisor and the modules currently loaded.

Enable path resolution logging:

```
$ vudebug +p
```

List some categories to see which ones are active:

```
$ vudebug ?ps
p +   PATH
s -   SYSCALL
```

PATH is active, SYSCALL is not active.

Disable all the categories:

```
$ vudebug -
```

Launch a bash and log syscall requests in red, path resolution in bold-blue, module choice in reverse green:

```
$ vudebug +s:r +p:b+ +c:g# -- bash
```


# SEE ALSO
umvu(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli
