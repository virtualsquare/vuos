#ifndef CANONICALIZE_H
#define CANONICALIZE_H

#include <sys/types.h>
#include <sys/stat.h>

#define FOLLOWLINK 1
#define PERMIT_NONEXISTENT_LEAF 2
#define IGNORE_TRAILING_SLASH 4
#define PERMIT_EMPTY_PATH 8

char *canon_realpath(const char *path, char *resolved_path, int flags, void *private);
 
char *canon_realpath_dup(const char *path, int flags, void *private);

/* canonicalize in virtual environments:
	 virtual-world consistent re-definition of functions needed for canonicalize */

struct canon_ops {
	/* link opaque (lstat) mode definition of file type, 0 for non-existent file */
	mode_t (*lmode) (const char *pathname, void *private);

	/* 0 if X_OK for euid egid or supplementary group, -1 otherwise */
	int (*dirxok) (const char *pathname, void *private);

	/* same as readlink(2) */
	ssize_t (*readlink) (const char *pathname, char *buf, size_t bufsiz, void *private);

	/* load in pathname the current pwd, return 0 upon success */
	int (*getcwd) (char *pathname, size_t size, void *private);

	/* load in pathname the current root relative to /, return 0 upon success */
	int (*getroot) (char *pathname, size_t size, void *private);
};

void canon_setops(struct canon_ops *ops);
#endif

