#ifndef VU_MOD_INHERITANCE_H
#define VU_MOD_INHERITANCE_H
#include <unistd.h>

/* it manages inheritance for modules */

/* the interface to modules is in include/vumodule.h */


/* vu_exec_setuid, vu_exec_setgid are used by vu_wrap_exec to
	 request setuid/setgid to uid/gid virtualization modules */

void vu_exec_setuid(uid_t uid);
void vu_exec_setgid(gid_t gid);
#endif
