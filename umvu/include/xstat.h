#ifndef VU_XSTAT_H
#define VU_XSTAT_H
#include <sys/stat.h>

/* define arrays having one element per file type */
#define S_MODE2TYPE(X) (((X) >> 12) & 0xf)
#define S_TYPES 16
#define S_TYPES_INIT(X) (X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X)

/* Table of file types:
 *   0 0000000 the file does not exist
 *   1 0010000 S_IFIFO
 *   2 0020000 S_IFCHR
 *   3 0030000 not assigned
 *   4 0040000 S_IFDIR
 *   5 0050000 not assigned
 *   6 0060000 S_IFBLK
 *   7 0070000 not assigned
 *   8 0100000 S_IFREG
 *   9 0110000 S_IFSIGNALFD
 *  10 0120000 S_IFLNK
 *  11 0130000 S_IFEVENTFD
 *  13 0150000 S_IFTIMERFD
 *  12 0140000 S_IFSOCK
 *  14 0160000 S_IFSTACK
 *  15 0170000 S_IFEPOLL
 */

/* define file types not currently handled in inodes */
#define S_IFEPOLL    __S_IFEPOLL
#define S_IFSTACK    __S_IFSTACK
#define S_IFSIGNALFD __S_IFSIGNALFD
#define S_IFTIMERFD  __S_IFTIMERFD
#define S_IFEVENTFD  __S_IFEVENTFD

#define __S_IFEPOLL    0170000 /* Epoll */
#define __S_IFSTACK    0160000 /* Stack */
#define __S_IFSIGNALFD 0110000 /* Signalfd */
#define __S_IFTIMERFD  0150000 /* Timerfd */
#define __S_IFEVENTFD  0130000 /* Eventfd */

#define S_ISEPOLL     __S_ISTYPE((mode), __S_IFEPOLL)
#define S_ISSTACK     __S_ISTYPE((mode), __S_IFSTACK)
#define S_ISESIGNALFD __S_ISTYPE((mode), __S_IFESIGNALFD)
#define S_ISETIMERFD  __S_ISTYPE((mode), __S_IFETIMERFD)
#define S_ISEEVENTFD  __S_ISTYPE((mode), __S_IFEEVENTFD)

#endif
