#ifndef VU_ACCESS_EMU_H
#define VU_ACCESS_EMU_H

#include <vu_execute.h>

/* this emulates 'access' given a stat buffer.
	 use getuid (or geteuid if AT_EACCESS), getgid (or getegid if AT_EACCESS)
	 and getgroups.
   return 0 or -errno
	 AT_SYMLINK_NOFOLLOW is handled by canonicalize/path-utils
*/
int vu_access_emu(struct vu_stat *statbuf, int mode, int flags);
#endif
