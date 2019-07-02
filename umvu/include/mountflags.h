#ifndef MOUNTFLAGS_H
#define MOUNTFLAGS_H

/* translate all mount flags into options so that modules can parse options only */
/* currently used by hashtable to set up the mount line (a' la /proc/mounts) */

/* opts == NULL: return the length of the char array required
else: translate  mountflags as a comma separated string of options in opts */

size_t mountflags2opts(unsigned long mountflags, char *opts, size_t optslen);

#endif
