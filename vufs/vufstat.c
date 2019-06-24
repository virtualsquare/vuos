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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <stropt.h>
#include <strcase.h>
#include <vumodule.h>
#include <vufstat.h>
#include <vufs_path.h>

#define EXT_CHAR 127
#define VSTATBUFLEN 1024
#define ARGMAXLEN 16
#define NELEM(X) (sizeof(X)/sizeof(*(X)))

#define VUFSTATPATH(vpath, path) \
	int _ ## path ## len = strlen(path) + 2; \
	char vpath[_ ## path ## len]; \
	snprintf(vpath, _ ## path ## len, "%s%c", (path), EXT_CHAR)

static int vufstat_open(int dirfd, const char *path, int flags) {
	VUFSTATPATH(vstatpath, path);
	if (flags & O_CREAT)
		vufs_create_path(dirfd, vstatpath, NULL, NULL);
	return openat(dirfd, vstatpath, flags, 0644);
}

void vufstat_unlink(int dirfd, const char *path) {
	VUFSTATPATH(vstatpath, path);
	if (unlinkat(dirfd, vstatpath, 0) == 0)
		vufs_destroy_path(dirfd, vstatpath);
}

int vufstat_link(int dirfd, const char *oldpath, const char *newpath) {
	VUFSTATPATH(oldvstatpath, oldpath);
	VUFSTATPATH(newvstatpath, newpath);
	return linkat(dirfd, oldvstatpath, dirfd, newvstatpath, 0);
}

int vufstat_rename(int dirfd, const char *oldpath, const char *newpath, int flags) {
	VUFSTATPATH(oldvstatpath, oldpath);
	VUFSTATPATH(newvstatpath, newpath);
	return syscall(__NR_renameat2, dirfd, oldvstatpath, dirfd, newvstatpath, flags);
}

static void vufstat_read(int vstatfd, char *buf, size_t size) {
	ssize_t n = read(vstatfd, buf, size - 1);
	if (n < 0) n = 0;
	buf[n] = 0;
}

static inline int vufstat_stropt(const char *input, char **tags, char **args, char *buf) {
	return stroptx(input, NULL, "\n", 0, tags, args, buf);
}

static void merge_timespec(struct timespec *ts, const char *s) {
	struct timespec nts;
	char *tail;
	nts.tv_sec = strtoul(s, &tail, 0);
	if (*tail == ',') {
		tail ++;
		nts.tv_nsec = strtoul(tail, NULL, 0);
	} else
		nts.tv_nsec = 0;
	if (nts.tv_sec > ts->tv_sec ||
			(nts.tv_sec == ts->tv_sec && nts.tv_nsec > ts->tv_nsec))
			*ts = nts;
}

static dev_t read_dev_t(const char *s) {
	int maj;
	int min;
	char *tail;
	maj = strtoul(s, &tail, 0);
	if (*tail == ',') {
		tail ++;
		min = strtoul(tail, NULL, 0);
	} else
		min = 0;
	return makedev(maj,min);
}

uint32_t vufstat_merge(int dirfd, const char *path, struct vu_stat *statbuf) {
	int vstatfd = vufstat_open(dirfd, path, O_RDONLY);
	uint32_t mask = 0;
	if (vstatfd >= 0) {
		char input[VSTATBUFLEN];
		int tagc;
		vufstat_read(vstatfd, input, VSTATBUFLEN);
		close(vstatfd);
		tagc = vufstat_stropt(input, NULL, NULL, 0);
		if(tagc > 0) {
			char *tags[tagc];
			char *args[tagc];
			vufstat_stropt(input, tags, args, input);
			for (int i = 0; tags[i]; i++) {
				if (args[i] != NULL) {
					switch (strcase(tags[i])) {
						case(STRCASE(t,y,p,e)):
							switch (args[i][0]) {
								case 's': statbuf->st_mode = (statbuf->st_mode & ~S_IFMT) | S_IFSOCK;
													mask |= VUFSTAT_TYPE;
													break;
								case '-':
								case 'f': statbuf->st_mode = (statbuf->st_mode & ~S_IFMT) | S_IFREG;
													mask |= VUFSTAT_TYPE;
													break;
								case 'c': statbuf->st_mode = (statbuf->st_mode & ~S_IFMT) | S_IFCHR;
													mask |= VUFSTAT_TYPE;
													break;
								case 'b': statbuf->st_mode = (statbuf->st_mode & ~S_IFMT) | S_IFBLK;
													mask |= VUFSTAT_TYPE;
													break;
							}
							break;
						case(STRCASE(m,o,d,e)):
							statbuf->st_mode = (statbuf->st_mode & S_IFMT) | (strtoul(args[i], NULL, 8) & ~S_IFMT);
							mask |= VUFSTAT_MODE;
							break;
						case(STRCASE(u,i,d)):
							statbuf->st_uid = strtoul(args[i], NULL, 0);
							mask |= VUFSTAT_UID;
							break;
						case(STRCASE(g,i,d)):
							statbuf->st_gid = strtoul(args[i], NULL, 0);
							mask |= VUFSTAT_GID;
							break;
						case(STRCASE(r,d,e,v)):
							statbuf->st_rdev = read_dev_t(args[i]);
							mask |= VUFSTAT_RDEV;
							break;
						case(STRCASE(d,e,v)):
							statbuf->st_dev = read_dev_t(args[i]);
							mask |= VUFSTAT_DEV;
							break;
						case(STRCASE(c,t,i,m,e)):
							merge_timespec(&statbuf->st_ctim, args[i]);
							mask |= VUFSTAT_CTIME;
							break;
					}
				}
				//printf("%s = %s\n",tags[i], args[i]);
			}
		}
	}
	return mask;
}

uint32_t vufstat_cmpstat(struct vu_stat *statbuf1, struct vu_stat *statbuf2) {
	uint32_t mask = 0;
	if (statbuf1->st_mode != statbuf2->st_mode) {
		if ((statbuf1->st_mode ^ statbuf2->st_mode) & ~S_IFMT)
			mask |= VUFSTAT_TYPE;
		if ((statbuf1->st_mode ^ statbuf2->st_mode) & S_IFMT)
			mask |= VUFSTAT_MODE;
	}
	if (statbuf1->st_uid != statbuf2->st_uid)
		mask |= VUFSTAT_UID;
	if (statbuf1->st_gid != statbuf2->st_gid)
		mask |= VUFSTAT_GID;
	if (statbuf1->st_rdev != statbuf2->st_rdev)
		mask |= VUFSTAT_RDEV;
	if (statbuf1->st_dev != statbuf2->st_dev)
		mask |= VUFSTAT_DEV;
	if (statbuf1->st_ctime != statbuf2->st_ctime)
		mask |= VUFSTAT_CTIME;
	return mask;
}

void vufstat_write(int dirfd, const char *path, struct vu_stat *statbuf, uint32_t mask) {
	if (mask == 0)
		vufstat_unlink(dirfd, path);
	else {
		int vstatfd = vufstat_open(dirfd, path, O_WRONLY | O_CREAT | O_TRUNC);
		if (vstatfd) {
			FILE *f = fdopen(vstatfd, "w+");
			if (mask & VUFSTAT_TYPE) {
				mode_t mode = statbuf->st_mode;
				int chartype = 0;
				switch (mode & S_IFMT) {
					case S_IFREG: chartype = 'f'; break;
					case S_IFSOCK: chartype = 's'; break;
					case S_IFCHR: chartype = 'c'; break;
					case S_IFBLK: chartype = 'b'; break;
				}
				if (chartype)
					fprintf(f,"type=%c\n", chartype);
			}
			if (mask & VUFSTAT_MODE)
				fprintf(f,"mode=0%o\n", statbuf->st_mode & ~S_IFMT);
			if (mask & VUFSTAT_UID)
				fprintf(f,"uid=%d\n", statbuf->st_uid);
			if (mask & VUFSTAT_GID)
				fprintf(f,"gid=%d\n", statbuf->st_gid);
			if (mask & VUFSTAT_RDEV)
				fprintf(f,"rdev=%d,%d\n", major(statbuf->st_rdev), minor(statbuf->st_rdev));
			if (mask & VUFSTAT_DEV)
				fprintf(f,"dev=%d,%d\n", major(statbuf->st_dev), minor(statbuf->st_dev));
			if (mask & VUFSTAT_CTIME)
				fprintf(f,"ctime=%ld,%ld\n", statbuf->st_ctim.tv_sec, statbuf->st_ctim.tv_nsec);
			fclose(f);
		}
	}
}

void vufstat_update(int dirfd, const char *path, struct vu_stat *statbuf, uint32_t mask, mode_t creat) {
	struct vu_stat tmpbuf;
	int oldmask = vufstat_merge(dirfd, path, &tmpbuf);
	if (oldmask) {
		if (mask & VUFSTAT_TYPE)
			tmpbuf.st_mode = (tmpbuf.st_mode & ~S_IFMT) | (statbuf->st_mode & S_IFMT);
		if (mask & VUFSTAT_MODE)
			tmpbuf.st_mode = (tmpbuf.st_mode & S_IFMT) | (statbuf->st_mode & ~S_IFMT);
		if (mask & VUFSTAT_UID)
			tmpbuf.st_uid = statbuf->st_uid;
		if (mask & VUFSTAT_GID)
			tmpbuf.st_gid = statbuf->st_gid;
		if (mask & VUFSTAT_RDEV)
			tmpbuf.st_rdev = statbuf->st_rdev;
		if (mask & VUFSTAT_DEV)
			tmpbuf.st_dev = statbuf->st_dev;
		if (mask & VUFSTAT_CTIME)
			tmpbuf.st_ctime = statbuf->st_ctime;
		vufstat_write(dirfd, path, &tmpbuf, oldmask | mask);
	} else if (creat & O_CREAT)
		vufstat_write(dirfd, path, statbuf, mask);
}
