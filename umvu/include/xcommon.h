#ifndef XCOMMON_H
#define XCOMMON_H

/* xfree and xstrdup does not break if the argument is NULL */

#define xfree(ptr) do { \
	if (ptr) \
	free(ptr); \
} while(0)

#define xstrdup(ptr) \
	(ptr ? strdup(ptr) : NULL)

#endif
