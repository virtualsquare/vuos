#ifndef VU_TMPDIR_h
#define VU_TMPDIR_h
#include <sys/types.h>

char *vu_tmpfilename(dev_t dev, ino_t inode, char *suffix);

char *vu_tmpdirpath(void);

#endif
