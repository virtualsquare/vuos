/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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

#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "canonicalize.h"

#define DOTDOT 1
#define ROOT 2

/* canonstruct: this struct contains the values that must be shared during the
	 whole recursive scan:
	 .ebuf: source for the relative to absolute path translation.
	   it is allocated on the stack.
	   if the path to translate begins by '/':
	   it contains the root dir followed by the path to translate,
	   otherwise
	   it contains the current working dir followed by the path to translate
	 .start, .end: pointers on ebuf, the boundaries of the current component
	 .resolved: the user provided buffer where the result must be stored
	 .rootlen: the len of the root component (it is not possible to generate
	   shorter pathnames to force the root cage. rootlen includes the '/')
	 .num_links: counter of symlink to avoid infinite loops (ELOOP)
	 .mode: lstat's st_mode of the last component (of the file at the end)
	   0 means non-existent -1 invalid (lstat must be called again).
	 .flags: flags (see canonicalize.h), follow link (final component)
	   this flag is for l-system calls like lstat, lchmod, lchown etc...
	   permit nonexistent leaves, etc.
	 .private: opaque arg for user provided access functions (lmode, readlink, getcwd, getroot).
 */

struct canonstruct {
	char ebuf[PATH_MAX];
	char *start;
	char *end;
	char *resolved;
	void *private;
	mode_t mode;
	short rootlen;
	short num_links;
	int flags;
};

static mode_t default_lmode(const char *pathname, void *private);
static ssize_t default_readlink(const char *pathname, char *buf, size_t bufsiz, void *private);
static int default_getcwd(char *pathname, size_t size, void *private);
static int default_getroot(char *pathname, size_t size, void *private);

/* default access functions */
static struct canon_ops operations = {
	.lmode = default_lmode,
	.readlink = default_readlink,
	.getcwd = default_getcwd,
	.getroot = default_getroot,
};

static mode_t default_lmode(const char *pathname, void *private) {
	struct stat buf[1];
	//printf("LMODE %s\n", pathname);
	if (lstat(pathname, buf) == 0)
		return buf->st_mode;
	else
		return 0;
}

static ssize_t default_readlink(const char *pathname, char *buf, size_t bufsiz, void *private) {
	return readlink(pathname, buf, bufsiz);
}

static int default_getcwd(char *pathname, size_t size, void *private) {
	return getcwd(pathname, size) ? 0 : -1;
}

static int default_getroot(char *pathname, size_t size, void *private) {
	strcpy(pathname, "/");
	return 0;
}

/* recursive generation of the canonicalized absolute path */
static int rec_realpath(struct canonstruct *cdata, char *dest)
{
	char *newdest;
	/* LOOP (***) This loop manages '.'
		 '..' (DOTDOT) from an inner call
		 ROOT if this is the root dir layer */
	while (1) {
		int lastlen;
		*dest = 0;
		/* delete multiple slashes / */
		while (*cdata->start == '/')
			cdata->start++;
		/* find the next component */
		for (cdata->end = cdata->start; *cdata->end && *cdata->end != '/'; ++cdata->end)
			;
		lastlen = cdata->end - cdata->start;
		/* '.': continue with the next component of the path, forget this */
		if (lastlen == 1 && cdata->start[0] == '.') {
			cdata->start=cdata->end;
			continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
		}
		if (lastlen == 2 && cdata->start[0] == '.' && cdata->start[1] == '.') {
			cdata->start=cdata->end;
			/* return DOTDOT only if this does not go outside the current root */
			if (dest > cdata->resolved+cdata->rootlen)
				return DOTDOT;
			else
				continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
		}
		/* nothing more to do */
		if (lastlen == 0) {
			if (cdata->mode == (unsigned) -1)
				cdata->mode = operations.lmode(cdata->resolved, cdata->private);
			errno = 0;
			return 0;
		}
		/* overflow check */
		if (dest + lastlen > cdata->resolved + PATH_MAX) {
			errno = ENAMETOOLONG;
			return -1;
		}
		/* add the new component */
		newdest=dest;
		if (newdest[-1] != '/')
			*newdest++='/';
		newdest=mempcpy(newdest,cdata->start,lastlen);
		*newdest=0;
		/* does the file exist? */
		if ((cdata->mode = operations.lmode(cdata->resolved, cdata->private)) == 0) {
			if ((cdata->flags & PERMIT_NONEXISTENT_LEAF) && errno == ENOENT && *cdata->end != '/') {
				errno = 0;
				return 0;
			} else
				/* forward the errno returned by lmode. */
				return -1;
		}
		/* Symlink case */
		if (S_ISLNK(cdata->mode) &&
				((*cdata->end == '/') || (cdata->flags & FOLLOWLINK)))
		{
			/* root dir must be already canonicalized.
				 symlinks navigating inside the root link are errors */
			if (dest < cdata->resolved+cdata->rootlen) {
				errno = ENOENT;
				return -1;
			} else
			{
				char buf[PATH_MAX];
				int len,n;
				/* test for symlink loops */
				if (++cdata->num_links > MAXSYMLINKS) {
					errno = ELOOP;
					return -1;
				}
				/* read the link */
				n = operations.readlink(cdata->resolved, buf, PATH_MAX-1, cdata->private);
				if (n < 0)  {
					return -1;
				}
				buf[n]=0;
				/* overflow check */
				len=strlen(cdata->end);
				if (n+len >= PATH_MAX) {
					errno = ENAMETOOLONG;
					return -1;
				}
				/* append symlink and remaining part of the path,
					 the latter part is moved inside ebuf itself */
				cdata->mode = -1;
				memmove(cdata->ebuf+n,cdata->end,len+1);
				cdata->end = memcpy(cdata->ebuf,buf,n);
				/* note that ebuf contains only the concatenation of the link target
					 and the reamining part of the original path.
					 The heading part of the source path can be lost but this is not a problem
					 as the recursion can invalidate part of the destination string;
					 in no cases there is the need to read some of the previous components
					 of the source path */	
				/* if the symlink is absolute the scan must return
					 back to the current root otherwise from the
					 same dir of the symlink */
				if (*buf == '/') {
					cdata->start=cdata->ebuf;
					/* if there is an absolute link in the main dir, do not return
						 ROOT (as this is the first invocation of the recursive function),
						 but just start the loop from the beginning */
					if (dest > cdata->resolved+1)
						return ROOT;
					else
						continue;  /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
				} else {
					cdata->start=cdata->end;
					continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
				}
			}
		}
		/* consistency checks on dirs:
			 all the components of the path but the last one must be
			 directories and must have 'x' permission */
		if (*cdata->end == '/') {
			if (!S_ISDIR(cdata->mode)) {
				errno = ENOTDIR;
				return -1;
			}
			/* check S_IXALL if requested */
			else if ((cdata->flags & CHECK_S_IXALL_ON_DIRS) && (cdata->mode & S_IXALL) != S_IXALL) {
				errno = EACCES;
				return -1;
			}
		}
		/* okay: recursive call for the next component */
		cdata->start=cdata->end;
		switch(rec_realpath(cdata,newdest)) {
			/* success. close recursion */
			case 0 : return 0;
							 /* DOTDOT: cycle at this layer */
			case DOTDOT:
							 cdata->mode = -1;
							 continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
							 /* ROOT: close recursive calls up the root */
			case ROOT:
							 cdata->mode = -1;
							 if (dest > cdata->resolved+cdata->rootlen)
								 return ROOT;
							 else
								 continue; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
							 /* Error */
			default: return -1;
		}
	}
}


/* absolute path: copy prefix in cdata->ebuf
return the length of the prefix
(not including trailing '/' as the path has a leading '/' already) */
static ssize_t abs_prefix(struct canonstruct *cdata) {
	char *root = cdata->ebuf;
	size_t prefixlen;
	operations.getroot(root, PATH_MAX, cdata->private);
	prefixlen = strlen(root);
	if (root[prefixlen - 1] == '/')
		prefixlen--;
	memcpy(cdata->ebuf, root, prefixlen);
	cdata->rootlen = prefixlen + 1;
	return prefixlen;
}

/* relative path: copy cwd in cdata->ebuf as a prefix
return the length of the prefix
(including a trailing '/' to catenate the path as it is)*/
static ssize_t rel_prefix(struct canonstruct *cdata) {
	char root[PATH_MAX];
	size_t rootlen;
	char *cwd = cdata->ebuf;
	size_t cwdlen;
	if (operations.getroot(root, PATH_MAX, cdata->private) < 0)
		return -1;
	rootlen = strlen(root);
	if (root[rootlen - 1] != '/')
		root[rootlen++] = '/';
	if (operations.getcwd(cwd, PATH_MAX, cdata->private) < 0)
		return -1;
	cwdlen = strlen(cwd);
	if (cwd[cwdlen-1] != '/')
		cwd[cwdlen++]='/';
	if (strncmp(cdata->ebuf,root,rootlen)==0)
		cdata->rootlen = rootlen;
	else
		cdata->rootlen = 1;
	return cwdlen;
}

/* realpath:
path: path to be canonicalized,
resolved_path: a buffer of PATH_MAX chars for the result
return resolved or NULL on failures.
errno is set consistently */
char *canon_realpath(const char *path, char *resolved_path, int flags, void *private)

{
	struct canonstruct cdata = {
		.resolved = resolved_path,
		.private = private,
		.flags = flags,
		.mode = operations.lmode("/", private),
		.num_links = 0};
	size_t pathlen;
	ssize_t prefixlen;
	/* arg consistency check */
	if (__builtin_expect(path == NULL, 0)) {
		errno = EINVAL;
		return NULL;
	}
	if (__builtin_expect(*path == 0, 0)) {
		if (flags & PERMIT_EMPTY_PATH &&
			operations.getcwd(resolved_path, PATH_MAX, private) >= 0)
			return resolved_path;
		else {
			errno = ENOENT;
			return NULL;
		}
	}
	pathlen = strlen(path);
	prefixlen = (*path == '/') ? abs_prefix(&cdata) : rel_prefix(&cdata);
	if (prefixlen < 0)
		return NULL;
	if (prefixlen + pathlen + 1 > PATH_MAX) {
		errno = ENAMETOOLONG;
		return NULL;
	}

	memcpy(cdata.ebuf + prefixlen, path, pathlen + 1);
	/* printf("PATH! %s (root=%*.*s file=%s)\n",cdata.ebuf,cdata.rootlen,cdata.rootlen,cdata.ebuf,cdata.ebuf+cdata.rootlen); */
	resolved_path[0]='/';
	cdata.start=cdata.ebuf+1;
	/* start the recursive canonicalization function */
	if (rec_realpath(&cdata,resolved_path+1) < 0) {
		*resolved_path=0;
		return NULL;
	} else {
		return resolved_path;
	}
}

char *canon_realpath_dup(const char *path, int flags, void *private) {
	char resolved_path[PATH_MAX];
	char *realpath = canon_realpath(path, resolved_path, flags, private);
	return realpath != NULL ? strdup(resolved_path) : NULL;
}

void canon_setops(struct canon_ops *ops) {
	operations = *ops;
}
