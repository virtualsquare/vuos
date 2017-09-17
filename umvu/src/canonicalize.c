#include <string.h>
#include <limits.h>
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
	 .statbuf: lstat of the last component (of the file at the end)
	 .flags: flags (see canonicalize.h), follow link (final component) and nonexisten leaves
	 this flag is for l-system calls like lstat, lchmod, lchown etc...
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

static int default_access(const char *pathname, int mode, void *private);
static mode_t default_lmode(const char *pathname, void *private);
static ssize_t default_readlink(const char *pathname, char *buf, size_t bufsiz);
static int default_getcwd(char *pathname, size_t size, void *private);
static int default_getroot(char *pathname, size_t size, void *private);

static struct canon_ops operations = {
	.access = default_access,
	.lmode = default_lmode,
	.readlink = default_readlink,
	.getcwd = default_getcwd,
	.getroot = default_getroot,
};

static int default_access(const char *pathname, int mode, void *private) {
	return access(pathname, mode);
}

static mode_t default_lmode(const char *pathname, void *private) {
	struct stat buf;
	if (lstat(pathname, &buf) == 0)
		return buf.st_mode;
	else
		return 0;
}

static ssize_t default_readlink(const char *pathname, char *buf, size_t bufsiz) {
	return readlink(pathname, buf, bufsiz);
}

static int default_getcwd(char *pathname, size_t size, void *private) {
	return getcwd(pathname, size) ? 0 : -1;
}

static int default_getroot(char *pathname, size_t size, void *private) {
	strcpy(pathname, "/");
	return 0;
}

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
			} else {
				errno = ENOENT; /* we could leave the errno returned by lmode. isn't it? */
				return -1;
			} 
		}
		/* Symlink case */
		if (S_ISLNK(cdata->mode) &&
				((*cdata->end == '/') || (cdata->flags & FOLLOWLINK)))
		{
			/* root dir must be already canonicalized.
				 symlinks navigating inside the root link are errors */
			if (dest <= cdata->resolved+cdata->rootlen) {
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
				n = operations.readlink(cdata->resolved, buf, PATH_MAX-1);
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
				memmove(cdata->ebuf+n,cdata->end,len+1);
				cdata->end = memcpy(cdata->ebuf,buf,n);
				/* if the symlink is absolute the scan must return
					 back to the current root otherwise from the
					 same dir of the symlink */
				if (*buf == '/') {
					cdata->start=cdata->ebuf;
					return ROOT;
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
			} else if (operations.access(cdata->resolved,X_OK,cdata->private) < 0) {
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
							 break; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
							 /* ROOT: close recursive calls up the root */
			case ROOT:
							 if (dest > cdata->resolved+cdata->rootlen)
								 return ROOT;
							 else
								 break; /* CONTINUE: NEXT ITERATION OF THE LOOP (***) */
							 /* Error */
			default: return -1;
		}
		*dest = 0;
		cdata->mode = operations.lmode(cdata->resolved, cdata->private);
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
	operations.getroot(root, PATH_MAX, cdata->private);
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
	if (!path || *path == 0) {
		errno = path ? ENOENT : EINVAL;
		return NULL;
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
