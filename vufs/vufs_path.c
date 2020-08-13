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
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <vufs_path.h>

void vufs_create_path(int dirfd, const char *path, create_path_cb_t callback, void *arg) {
	int pathlen = strlen(path);
	char tpath[pathlen];
	int i;
	for (i = 0; i < pathlen; i++) {
		if (path[i] == '/') {
			tpath[i] = 0;
			if (mkdirat(dirfd, tpath, 0700) == 0 && callback)
				callback(arg, dirfd, tpath);
		}
		tpath[i] = path[i];
	}
}

void vufs_destroy_path(int dirfd, const char *path) {
	int pathlen = strlen(path);
	char tpath[pathlen];
	int i;
	strncpy(tpath, path, pathlen);
	for (i = pathlen - 1; i >= 0; i--) {
		if (tpath[i] == '/') {
			tpath[i] = 0;
			if (unlinkat(dirfd, tpath, AT_REMOVEDIR) < 0)
				break;
		}
	}
}

static int skipdir(const char *name) {
	if (name[0] == 0 || name[0] != '.')
		return 0;
	if (name[1] == 0)
		return 1;
	if (name[1] == '.' && name[2] == 0)
		return 1;
	return 0;
}

void vufs_destroy_tree(int dirfd, const char *path, int recursive) {
	int retval = unlinkat(dirfd, path, 0);
	if (retval < 0 && errno == EISDIR) {
		retval = unlinkat(dirfd, path, AT_REMOVEDIR);
		if (retval < 0 && (errno == ENOTEMPTY || errno == EEXIST)) {
			int fd = openat(dirfd, path, O_RDONLY | O_DIRECTORY);
			if (fd >= 0) {
				DIR *dir;
				struct dirent *de;
				dir = fdopendir(fd);
				if (dir) {
					while ((de = readdir(dir)) != NULL) {
						if (skipdir(de->d_name) == 0) {
							if (recursive)
								vufs_destroy_tree(fd, de->d_name, recursive);
							else
								unlinkat(fd, de->d_name, 0);
						}
					}
					closedir(dir);
				}
			}
			unlinkat(dirfd, path, AT_REMOVEDIR);
		}
	}
}

int vufs_whiteout(int dirfd, const char *path) {
	if (dirfd >= 0) {
		vufs_destroy_tree(dirfd, path, 0);
		vufs_create_path(dirfd, path, NULL, NULL);
		return mknodat(dirfd, path, S_IFREG | 0644, 0);
	} else
		return 0;
}

void vufs_dewhiteout(int dirfd, const char *path) {
	if (dirfd >= 0) {
		if (unlinkat(dirfd, path, 0) == 0)
			vufs_destroy_path(dirfd, path);
	}
}
