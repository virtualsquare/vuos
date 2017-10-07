#ifndef VU_XSTAT_H
#define VU_XSTAT_H
#include <sys/stat.h>

#define S_MODE2TYPE(X) (((X) >> 12) & 0xf)
#define S_TYPES 16
#define S_TYPES_INIT(X) (X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X),(X)

#define S_IFEPOLL  __S_IFEPOLL
#define S_IFSIGNALFD __S_IFSIGNALFD
#define S_IFTIMERFD __S_IFTIMERFD
#define S_IFEVENTFD __S_IFEVENTFD

#define __S_IFEPOLL  0170000 /* Epoll */
#define __S_IFSIGNALFD 0x160000 /* Signalfd */
#define __S_IFTIMERFD 0x150000 /* Timerfd */
#define __S_IFEVENTFD 0x130000 /* Eventfd */

#define S_ISEPOLL __S_ISTYPE((mode), __S_IFEPOLL)
#define S_ISESIGNALFD __S_ISTYPE((mode), __S_IFESIGNALFD)
#define S_ISETIMERFD __S_ISTYPE((mode), __S_IFETIMERFD)
#define S_ISEEVENTFD __S_ISTYPE((mode), __S_IFEEVENTFD)

#endif
