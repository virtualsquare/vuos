#ifndef _VULIB_H
#define _VULIB_H
#include <unistd.h>
#include <sys/utsname.h>

#define __VVU_insmod -1
#define __VVU_rmmod -2
#define __VVU_lsmod -3
#define __VVU_vuctl -4

#define __NR_vu_insmod __VVU_insmod
#define __NR_vu_rmmod __VVU_rmmod
#define __NR_vu_lsmod __VVU_lsmod
#define __NR_vuctl __VVU_vuctl

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
#define DEBUG_ALLTAGS " ABCDEFGHIJKLMNOPQRSTUVWXYZ_01234abcdefghijklmnopqrstuvwxyz56789"
#define DEBUG_NTAGS sizeof(DEBUG_ALLTAGS)

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

static inline long vu_get_debugtags(char *debugtags, size_t len) {
	return syscall(__NR_vuctl, VUCTL_GET_DEBUGTAGS, debugtags, len);
}

static inline long vu_add_debugtags(char *debugtags) {
	return syscall(__NR_vuctl, VUCTL_ADD_DEBUGTAGS, debugtags);
}

static inline long vu_del_debugtags(char *debugtags) {
	return syscall(__NR_vuctl, VUCTL_DEL_DEBUGTAGS, debugtags);
}

static inline long vu_get_debugtagname(int tag, char *string, size_t len) {
	return syscall(__NR_vuctl, VUCTL_GET_DEBUGTAGNAME, tag,  string, len);
}

static inline long vu_set_debugcolor(char *debugcolor) {
	return syscall(__NR_vuctl, VUCTL_SET_DEBUGCOLOR, debugcolor);
}

#endif
#endif
