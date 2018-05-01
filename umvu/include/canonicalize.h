#ifndef CANONICALIZE_H
#define CANONICALIZE_H

#include <sys/types.h>
#include <sys/stat.h>

/* if FOLLOWLINK == 0 and pathname is a symlink then it returns
	 the realpath of the link itself instead of the realpath of
	 the file it refers to */
#define FOLLOWLINK 1
/* if PERMIT_NONEXISTENT_LEAF == 1 the pathname may refer to a non-existent
	 file (inside an existing directory) */
#define PERMIT_NONEXISTENT_LEAF 2
/* if PERMIT_EMPTY_PATH == 1 and pathname is an empty string it returns the
	 cwd (or what the getcwd helper function returns).
	 if PERMIT_EMPTY_PATH == 0 and pathname is an empty string realpath returns -1/ENOENT */
#define PERMIT_EMPTY_PATH 4
/* if CHECK_S_IXGRP_ON_DIRS == 1 canon_realpath returns -1/EACCES if S_IXGRP is
	 not set in the return value of lmode for one of the directories in the path
	 (unsupported) */
#define CHECK_S_IXOTH_ON_DIRS 8

char *canon_realpath(const char *path, char *resolved_path, int flags, void *private);

char *canon_realpath_dup(const char *path, int flags, void *private);

/* canonicalize in virtual environments:
	 virtual-world consistent re-definition of functions needed for canonicalize */

struct canon_ops {
	/* link opaque (lstat) mode_t definition of file type, 0 for non-existent file */
	/* when CHECK_S_IXGRP_ON_DIRS == 1, S_IXGRP means search permission on directories.
		 if CHECK_S_IXGRP_ON_DIRS == 1 and S_IXGRP is unset for lmode's return value then
		 any further path-resolution step inside that directory is forbidden and realpath
		 returns -1/EACCES */
	mode_t (*lmode) (const char *pathname, void *private);

	/* same as readlink(2) */
	ssize_t (*readlink) (const char *pathname, char *buf, size_t bufsiz, void *private);

	/* load in pathname the current pwd, return 0 upon success */
	int (*getcwd) (char *pathname, size_t size, void *private);

	/* load in pathname the current root relative to /, return 0 upon success */
	int (*getroot) (char *pathname, size_t size, void *private);
};

void canon_setops(struct canon_ops *ops);
#endif

