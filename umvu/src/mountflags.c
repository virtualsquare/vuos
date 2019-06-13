/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mount.h>

/* translate all mount flags into options so that modules can parse options only */

char *mountflag_strings[32] = {
	"ro", // 1
	"nosuid", // 2
	"nodev", // 4
	"noexec", // 8
	"sync", // 16
	"remount", // 32
	"mand", // 64
	"dirsync", // 128
	NULL, // 256
	NULL, // 512
	"noatime", // 1024
	"nodiratime", // 2048
	"bind", // 4096
	"move", // 8192
	"rec", // 16384
	"silent", // 32768
	"acl", // 1 << 16
	"unbindable", // 1 << 17
	NULL, // 1 << 18 (MS_PRIVATE)
	NULL,  // 1 << 19 (MS_SLAVE)
	NULL, // 1 << 20 (MS_SHARED)
	"relatime", // 1 << 21
	NULL, // 1 << 22 (MS_KERNMOUNT)
	"iversion", // 1 << 23 (MS_IVERSION)
	"strictatime", // 1 << 24
	"lazytime", // 1 << 25
	NULL, // 1 << 26
	NULL, // 1 << 27
	NULL, // 1 << 28
	NULL, // 1 << 29
	NULL, // 1 << 30 (MS_ACTIVE)
	"nouser", // 1 << 31 (MS_NOUSER)
};

static char *strlcpy(char *dst, char *src, char *limit) {
	while (*src && dst < limit - 1)
		*dst++ = *src++;
	*dst = 0;
	return dst;
}

size_t mountflags2opts(unsigned long mountflags, char *opts, size_t optslen) {
	int i;
	if (opts) {
		char *limit = opts + optslen;
		char *nextopt = opts;
		*nextopt = 0;
		if (mountflags & 1)
			nextopt = strlcpy(nextopt, mountflag_strings[0], limit);
		else
			nextopt = strlcpy(nextopt, "rw", limit);
		for (i = 1; i < 32; i++) {
			if ((mountflags & (1UL << i)) && (mountflag_strings[i])) {
				nextopt = strlcpy(nextopt, ",", limit);
				nextopt = strlcpy(nextopt, mountflag_strings[i], limit);
			}
		}
		return (nextopt - opts) + 1;
	} else {
		size_t retval = 3;
		for (i = 1; i < 32; i++) {
			if ((mountflags & (1UL << i)) && (mountflag_strings[i]))
				retval += strlen(mountflag_strings[i]) + 1;
		}
		return retval;
	}
}

#if 0
int main() {
	unsigned long flags = 0; //0xffffffff;
	size_t len = mountflags2opts(flags, NULL, 0);
	char str[len];
	printf("%d %d\n", len, mountflags2opts(flags, str, len));
	printf("%s %d\n", str, strlen(str));
}
#endif
