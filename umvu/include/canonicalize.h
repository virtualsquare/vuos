#ifndef CANONICALIZE_H
#define CANONICALIZE_H

#include <sys/types.h>
#include <sys/stat.h>

#define FOLLOWLINK 1
#define PERMIT_NONEXISTENT_LEAF 2
#define IGNORE_TRAILING_SLASH 4

struct canon_ops {
	int (*access) (const char *pathname, int mode, void *private);
	mode_t (*lmode) (const char *pathname, void *private);
	ssize_t (*readlink) (const char *pathname, char *buf, size_t bufsiz, void *private);
	int (*getcwd) (char *pathname, size_t size, void *private);
	int (*getroot) (char *pathname, size_t size, void *private);
};

char *canon_realpath(const char *path, char *resolved_path, int flags, void *private);
 
char *canon_realpath_dup(const char *path, int flags, void *private);

void canon_setops(struct canon_ops *ops);
#endif

