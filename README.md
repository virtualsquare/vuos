# VUOS: give your processes a new VU #

VUOS is a Virtual Operating System implemented at user space. Currently it
implements about 150 Linux-compatible system calls providing support for a
wide range of applications. Each process or even each thread in VUOS can see a
different execution environment: file system contents, networking, devices,
user ids etc.  The main idea behind VUOS is that it is possible to
give processes their own "view" using partial virtual machines.

VUOS is a different perspective on namespaces, anykernels and related concepts.

A partial virtual machine intercepts the system call requests and operates like
a filter: system call can be forwarded to the kernel of the hosting system or
processed by the partial virtual machine hypervisor.

```
          Processes
              v
    +------------------+
    |  PSV hypervisor  | --> virtualizing modules
    +------------------+
              v
       (linux) kernel
```

In this way processes can see a *mix* of resources provided by the kernel (on which they have
the same *view* of the other processes) and virtual resource.
It is possible to mount filesystems, load networking stack, change the structure of the file system
tree, create virtual devices.

The hypervisor is just a user process so while it gives new perspective for processes, **it does not widen
the attack surface of the kernel**.

## Some examples ##
... just to show something VUOS is capable of.
NB: VUOS is much much more than this, and it is under active developmemnt.

### mount a file system image (using fuse virtual device) ###

This example uses **umvu**: a user-mode implementation of the VUOS concepts based on ptrace. In the future VUOS
could be re-implemented on other tracing/virtualizing supports.

start the hypervisor, and run a bash *inside* the partial virtual machine

    $ umvu bash

This is the prompt of the partial virtualized shell, let us change it to $$ to show the difference

    $ PS1='\$\$ '

let us load vufuse: a user-mode implementation of FUSE (source compatible with FUSE modules)

    $$ vu_insmod fuse

nothing is currently mounted on /mnt

    $$ ls /mnt

run the FUSE handler program (it uses the virtual /dev/fuse)
		$$ fuse-ext2 -o ro /tmp/linux.img /mnt

now the image has been mounted:

    $$ ls /mnt
    bin  boot  dev  etc  lib  lost+found  mnt  proc  sbin  tmp  usr
    $$ vuumount /mnt
    $$ ls /mnt
    $$ exit

We have left the partial virtual machine

Comments: user can *mount* any filesystem they like, on any directory. The linux kernel is not involved
for all the system calls related to files in the mounted filesystem. The effects of this *mount* is just *perceived* by the processes running in the partial virtual machine. `vumount` is just a wrapper to the `mount(1)` system call (the command `mount(8)` does much much more, it is setuid root and requires real uid to be root to
permit filesystem mounting (`mount(8)` works in `umvu` adding a module of uid/gid virtualization).

### mount a file system image (using vufuse) ###

start the hypervisor, and run a bash *inside* the partial virtual machine

    $ umvu bash

This is the prompt of the partial virtualized shell, let us change it to $$ to show the difference

    $ PS1='\$\$ '

let us load vufuse: a user-mode implementation of FUSE (source compatible with FUSE modules)

    $$ vu_insmod vufuse

nothing is currently mounted on /mnt

    $$ ls /mnt
    the following command mounts the filesystem image /tmp/linux.img
    $$ vumount -t vufuseext2 -o ro /tmp/linux.img /mnt

now the image has been mounted:

    $$ ls /mnt
    bin  boot  dev  etc  lib  lost+found  mnt  proc  sbin  tmp  usr
    $$ vuumount /mnt
    $$ ls /mnt
    $$ exit

We have left the partial virtual machine

### create a disk image, partition it, create a filesystem and mount it ###

start the hypervisor, and run a bash *inside* the partial virtual machine

    $ umvu bash

This is the prompt of the partial virtualized shell, let us change it to $$ to show the difference

    $ PS1='\$\$ '

let us load vudev and fuse: vudev to virtualize devices and fuse as in the previous example

    $$ vu_insmod vudev fuse

Note: it is possible to use vufuse instead of fuse. the command is `vu_insmod vudev vufuse`.

create a 1 GiB large empty file

    $$ truncate -s 1G /tmp/disk
    $$ ls -l /tmp/disk
    -rw-r--r-- 1 renzo renzo 1073741824 Jun  3 11:55 /tmp/disk

let us mount the empty file as a partitioned virtual disk:

    $$ vumount -t vudevpartx /tmp/disk /dev/hda
    Bad MBR signature 0 0

clearly if not a partitioned disk, yet. Let us add a partitioning scheme:

    $$  /sbin/gdisk /dev/hda
    GPT fdisk (gdisk) version 1.0.3

    Partition table scan:
      MBR: not present
      BSD: not present
      APM: not present
      GPT: not present

    Creating new GPT entries.

    Command (? for help):  n
    Partition number (1-128, default 1):
    First sector (34-2097118, default = 2048) or {+-}size{KMGTP}:
    Last sector (2048-2097118, default = 2097118) or {+-}size{KMGTP}: +200M
    Current type is 'Linux filesystem'
    Hex code or GUID (L to show codes, Enter = 8300):
    Changed type of partition to 'Linux filesystem'

    Command (? for help): n
    Partition number (2-128, default 2):
    First sector (34-2097118, default = 411648) or {+-}size{KMGTP}:
    Last sector (411648-2097118, default = 2097118) or {+-}size{KMGTP}:
    Current type is 'Linux filesystem'
    Hex code or GUID (L to show codes, Enter = 8300):
    Changed type of partition to 'Linux filesystem'

    Command (? for help): p
    Disk /dev/hda: 2097152 sectors, 1024.0 MiB
    Sector size (logical): 512 bytes
    Disk identifier (GUID): F2A76123-73ED-4052-BAFE-6B37473E6187
    Partition table holds up to 128 entries
    Main partition table begins at sector 2 and ends at sector 33
    First usable sector is 34, last usable sector is 2097118
    Partitions will be aligned on 2048-sector boundaries
    Total free space is 2014 sectors (1007.0 KiB)

    Number  Start (sector)    End (sector)  Size       Code  Name
       1            2048          411647   200.0 MiB   8300  Linux filesystem
       2          411648         2097118   823.0 MiB   8300  Linux filesystem

    Command (? for help): w

    Final checks complete. About to write GPT data. THIS WILL OVERWRITE EXISTING
    PARTITIONS!!

    Do you want to proceed? (Y/N): Y
    OK; writing new GUID partition table (GPT) to /dev/hda.
    The operation has completed successfully.

The disk has been partitioned:

    $$  ls -l /dev/hda1
    brw------- 0 renzo renzo 0, 1 Jan  1  1970 /dev/hda1
    $$ ls -l /dev/hda2
    brw------- 0 renzo renzo 0, 2 Jan  1  1970 /dev/hda2

Now it is possible to create an ext4 partition on /dev/hda1

    $$ /sbin/mkfs.ext4 /dev/hda1
    mke2fs 1.45.1 (12-May-2019)
    warning: Unable to get device geometry for /dev/hda1
    Creating filesystem with 204800 1k blocks and 51200 inodes
    Filesystem UUID: c96c6499-40cd-43df-addf-52e06d7e6842
    Superblock backups stored on blocks:
            8193, 24577, 40961, 57345, 73729

    Allocating group tables: done
    Writing inode tables: done
    Creating journal (4096 blocks): done
    Writing superblocks and filesystem accounting information: done

now the file system on /dev/hda1 can be mounted on /mnt

    $$ fuse-ext2 -o rw+ /dev/hda1 /mnt

Note: the mount command for vufuse instead of fuse is `vumount -t vufuseext2 -o rw+ /dev/hda1 /mnt`

add a significative file on /mnt

    $$ echo ciao > /mnt/hello
    $$ ls -l /mnt
    total 13
    -rw-r--r-- 1 renzo renzo     5 Jun  3 12:09 hello
    drwx------ 2 root  root  12288 Jun  3 12:06 lost+found
    $$ vuumount /mnt
    $$ vuumount /dev/hda
    $$ exit
    $

### mount a user-level networking stack ###

It is possible to provide network partial virtualization using the `vunet` module

start the hypervisor, and run a bash *inside* the partial virtual machine

    $ umvu bash

This is the prompt of the partial virtualized shell, let us change it to $$ to show the difference

    $ PS1='\$\$ '

let us load vunet

    $$ vu_insmod vunet

the following command *mounts* a vde network on /dev/net/myvde using libioth.
(see https://github.com/rd235/vdeplug4) (any ioth supported stack can be used. The mount source argument
is the stack implementation to use, vdestack in this example).

    $$ vumount -t vunetioth -o vxvde:// vdestack /dev/net/myvde

Alternatively: the following command uses a vunet specific implementation of vdestack:

    $$ vumount -t vunetvdestack vxvde:// /dev/net/myvde

vustack is the command to select the stack to use.

    $$ vustack /dev/net/myvde ip link
    1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
        link/ether 7e:76:c0:d7:3b:37 brd ff:ff:ff:ff:ff:ff

without vustack I can still access the stack provided by the linux kernel

    $$ ip link
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
        link/ether 80:aa:bb:cc:dd:ee brd ff:ff:ff:ff:ff:ff

let us start a bash using /dev/net/myvde as itsdfault net

    $$ vustack /dev/net/myvde bash
    $ PS1='\$N\$ '

let us configure the net

    $N$ ip addr add 192.168.250.250/24 dev vde0
    $N$ ip link set vde0 up
    $N$ ip route add default via 192.168.250.1
    $N$ ip addr
    1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    2: vde0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
        link/ether 7e:76:c0:d7:3b:37 brd ff:ff:ff:ff:ff:ff
        inet 192.168.250.250/24 scope global vde0
           valid_lft forever preferred_lft forever
        inet6 fe80::7c76:c0ff:fed7:3b37/64 scope link
           valid_lft forever preferred_lft forever
    $N$ ip route
    default via 192.168.250.1 dev vde0
    192.168.250.0/24 dev vde0 proto kernel scope link src 192.168.250.250
    $N$ ping 80.80.80.80
    PING 80.80.80.80 (80.80.80.80) 56(84) bytes of data.
    64 bytes from 80.80.80.80: icmp_seq=1 ttl=52 time=56.9 ms
    64 bytes from 80.80.80.80: icmp_seq=2 ttl=52 time=57.9 ms
    ^C
    $N$

## Structure of umvu ##

`umvu` has a three layer architecture:

* core `umvu` hypervisor
* modules (e.g. `vufuse, vunet, vufs, vudev`)
* submodules (e.g. vufuseext2, vudevpartx, vudevnull, vunetvdestack

`umvu` traces all the system call requests generated by the processes *and by the modules* and decides if the request is *real* or *virtual* and in this latter case which is the module to reroute the request.
Absolute pathnames, file descriptors, family of protocols, ioctl tags, syscall number can be used to select the right module.

Modules register their `boundary of responsibility` to the core hypervisor: i.e. which path prefixes, file descriptors,
etc. they are responsible for.
The API of modules consists of a subset of the system call API. When a process uses a read system call on a virtualized
file (e.g. a file in a vumounted partition), the corresponding module receives a read request having the same signature
of the standard system call. As an example the test module test\_modules/unreal.c, provides a *view* of the entire file
system in `/unreal`  and in `/unreal/unreal` simply using the system calls as module methods. (e.g. the function to implement
lstat in the module is lstat, and so on. The only two function that had to be defined were: `getdents64` as gliibc does not provide an interface to it and `access` as it lacks a `flags` argument).

The API between modules and submodules is tailored to the specific requirements. The API for filesystems has been chose to
provide source level compatibility with FUSE modules.

## Installing umvu ##

In order to test umvu several libraries and helper tools are required.
The tests here above have been run on debian sid.
<!--
There is a docker recipe and a script to create a test environment here:
    https://github.com/gufoe/vuos-tutorial
-->

For the sake of compleness (and hopefully clarity), it is possible to install all the code by hand, step by step
as briefly explained in the following.

First of all install the following packets:

    git python3 build-essential cmake make autogen autoconf libtool libcap-dev libattr1-dev libfuse-dev libexecs-dev
    libssl1.0-dev libmhash-dev libpam0g-dev libfuse-dev e2fsprogs comerr-dev e2fslibs-dev libpam-dev libmhash-dev

Then install libraries and tools from the following list of git repositories:

    https://github.com/rd235/strcase.git
    https://github.com/virtualsquare/vde-2.git
    https://github.com/rd235/vdeplug4.git
    https://github.com/virtualsquare/purelibc.git
    https://github.com/rd235/libvolatilestream.git
    https://github.com/rd235/libstropt.git
    https://github.com/rd235/libfduserdata.git
    https://github.com/rd235/libvpoll-eventfd.git
    https://github.com/rd235/libvdestack.git
    https://github.com/rd235/vdeplug_vlan.git
    https://github.com/rd235/cado.git
    https://github.com/alperakcan/fuse-ext2.git
    https://github.com/rd235/vdeplug_agno.git
    https://github.com/rd235/vdens.git
    https://github.com/virtualsquare/libioth.git
    https://github.com/virtualsquare/vuos.git

A symbolic link is required to make vufuseext2 reachable in the right dir

    ln -s  /usr/local/lib/umview/modules/umfuseext2.so /usr/local/lib/vu/modules/vufuseext2.so
