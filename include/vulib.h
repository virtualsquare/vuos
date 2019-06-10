#ifndef _VULIB_H
#define _VULIB_H
#include <unistd.h>
#include <sys/utsname.h>

/* header file of libvulib.
	 This library is for programs running in VUOS virtual machines.
	 it provides access to the syscalls added by VUOS,
	 if defines constants and structs for the syscalls */

/* Virtual System call numbers */
#define __VVU_insmod -1
#define __VVU_rmmod -2
#define __VVU_lsmod -3
#define __VVU_vuctl -4
#define __VVU_msocket -5

#define __NR_vu_insmod __VVU_insmod
#define __NR_vu_rmmod __VVU_rmmod
#define __NR_vu_lsmod __VVU_lsmod
#define __NR_vuctl __VVU_vuctl
#define __NR_msocket __VVU_msocket

/* constants for vuctl */
#define VUCTL_GETINFO 1
#define VUCTL_SETNAME 2
#define VUCTL_GET_DEBUGTAGS 3
#define VUCTL_ADD_DEBUGTAGS 4
#define VUCTL_DEL_DEBUGTAGS 5
#define VUCTL_GET_DEBUGTAGNAME 6
#define VUCTL_SET_DEBUGCOLOR 7
#if 0
/* not yet implemented */
#define VUCTL_ATTACH
#endif

/* in VUOS network stacks can be "mounted" in the file system.
	 S_IFSTACK is the file type of a network stack */
#ifndef S_IFSTACK
#define S_IFSTACK 0160000
#endif
/* 0 is not a valid socket type, it is used by msocket
	 to define the default stack for a give family:
	 msocket("/dev/net/mystack", AF_INET, SOCK_DEFAULT, 0);
	 sets the default stack for ipv4 socket to "/dev/net/mystack" */
#ifndef SOCK_DEFAULT
#define SOCK_DEFAULT 0
#endif

/* debug tags for vuctl VUCTL_*_DEBUGTAGS */
#define DEBUG_ALLTAGS " ABCDEFGHIJKLMNOPQRSTUVWXYZ_01234abcdefghijklmnopqrstuvwxyz56789"
#define DEBUG_NTAGS sizeof(DEBUG_ALLTAGS)

/* struct for vuctl VUCTL_GETINFO */
struct vu_info {
  struct utsname uname;
  char vu_serverid[_UTSNAME_LENGTH];
  char vu_name[_UTSNAME_LENGTH];
};

#ifndef _VU_HYPERVISOR

static inline long vu_insmod(char *module, int permanent) {
	return syscall(__NR_vu_insmod, module, permanent);
}

static inline long vu_rmmod(char *modname) {
	return syscall(__NR_vu_rmmod, modname);
}

static inline long vu_lsmod(char *buf, size_t len) {
	return syscall(__NR_vu_lsmod, buf, len);
}

static inline long vu_getinfo(struct vu_info *info) {
	return syscall(__NR_vuctl, VUCTL_GETINFO, info);
}

static inline long vu_check(void) {
	return syscall(__NR_vuctl, VUCTL_GETINFO, NULL);
}

static inline long vu_setname(char *vuname) {
	return syscall(__NR_vuctl, VUCTL_SETNAME, vuname);
}

static inline long vu_get_debugtags(char *debugtags, size_t len, int local) {
	return syscall(__NR_vuctl, VUCTL_GET_DEBUGTAGS, debugtags, len, local);
}

static inline long vu_add_debugtags(char *debugtags, int local) {
	return syscall(__NR_vuctl, VUCTL_ADD_DEBUGTAGS, debugtags, local);
}

static inline long vu_del_debugtags(char *debugtags, int local) {
	return syscall(__NR_vuctl, VUCTL_DEL_DEBUGTAGS, debugtags, local);
}

static inline long vu_get_debugtagname(int tag, char *string, size_t len) {
	return syscall(__NR_vuctl, VUCTL_GET_DEBUGTAGNAME, tag,  string, len);
}

static inline long vu_set_debugcolor(char *debugcolor) {
	return syscall(__NR_vuctl, VUCTL_SET_DEBUGCOLOR, debugcolor);
}

static inline long msocket(char *stack, int domain, int type, int protocol) {
	return syscall(__NR_msocket, stack, domain, type, protocol);
}

#endif
#endif
