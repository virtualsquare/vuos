/*
 *   VUOS: view OS project
 *   Copyright (C) 2020  Renzo Davoli <renzo@cs.unibo.it>
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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <vu_execute.h>
#include <vu_access_emu.h>

static int _is_group_member(gid_t gid) {
	int len = getgroups(0, NULL);
	gid_t list[len];
	int i;
	len = getgroups(len, list);
	for (i = 0; i < len; i++) {
		if (gid == list[i])
			return 1;
	}
	return 0;
}

int vu_access_emu(struct vu_stat *statbuf, int mode, int flags) {
	if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW))
		return -EINVAL;

	if (statbuf->st_mode == 0)
		return -ENOENT;

	if (mode == F_OK)
		return 0;

	uid_t uid = (flags & AT_EACCESS) ? geteuid() : getuid();

	if (uid == 0) { // it is root
		if ((mode & X_OK) == 0) // RW are always allowed
			return 0;
		// X OK is X is okay for someone
		if (statbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
			return 0;
	}

	int granted;

	if (uid == statbuf->st_uid)
		// user permissions
		granted = (int) ((statbuf->st_mode >> 6) & mode);
	else {
		gid_t gid = (flags & AT_EACCESS) ? getegid() : getgid();
		if (statbuf->st_gid == gid || _is_group_member(statbuf->st_gid))
			// group permissions
			granted = (int) ((statbuf->st_mode >> 3) & mode);
		else
			// other permissions
			granted = statbuf->st_mode & mode;
	}

	if (granted == mode)
		return 0;

	return -EACCES;
}
