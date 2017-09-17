#ifndef XCOMMON_H
#define XCOMMON_H

#define xfree(ptr) do { \
	if (ptr) \
	free(ptr); \
} while(0)

#define xstrdup(ptr) \
	(ptr ? strdup(ptr) : NULL)

#endif
