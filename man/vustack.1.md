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

`vustack` -- set the default networking stack

# SYNOPSIS

`vustack` [*options* ...] *stack* *command* [*args*]

# DESCRIPTION

`vunet` is the VUOS module for networking virtualization. Networking
stacks can be loaded using `vumount`(1) and are identified by a pathname:
the mount point. `vustack` selects the stack to use among those available;
*command* runs using the stack selected `vustack`.

# OPTIONS

  `-h`, `--help`
: Print a short help message and exit. If combined with `-v` print also
: the list of protocol family names.

  `-s`, `--supported`
: select the stack only for the protocol families supported by *stack*.

  `-f` *list*, `--family` *list*, `--families` *list*
: select the stack for the protocol families in *list*. *list* is a
: comma separated list of protocol names or numbers.

  `-v`, `--verbose`
: print the list of protocol families object of the stack selection.

# EXAMPLES

Load `vunet` and mount a stack:

```
$ vu_insmod vunet
$ vumount -t vunetvdestack vde:// /dev/net/vde
```

Run *ip link* using the stack mounted in /dev/net/vde:

```
$ vustack /dev/net/vde ip link
1: lo: *LOOPBACK* mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: *BROADCAST,MULTICAST* mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 5a:1e:97:fa:ab:a3 brd ff:ff:ff:ff:ff:ff
```

Run *ip link set vde0 up* selecting /dev/net/vde only for the families supported by vunetvdestack:

```
$ vustack -s -v /dev/net/vde ip link set vde0 up
Using /dev/net/vde for the following address families:
    inet(2) inet6(10) netlink(16) packet(17)
```

mount a null stack and use it to disable netlink:

```
$ vumount -t vunetnull vde:// /dev/net/null
$ exec vustack -f netlink -v /dev/net/null bash
Using /dev/net/null for the following address families:
    netlink(16)
$ ip addr
Cannot open netlink socket: Address family not supported by protocol
```

# SEE ALSO
umvu(1), vumount(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli
