#ifndef VUMODULE_H
#define VUMODULE_H
#include <stdint.h>
#include <stdarg.h>

struct vu_service_t;
struct hashtable_obj_t;

struct vu_module_t {
  char *name;
  char *description;
	struct vu_service_t *service;
};

typedef long (*syscall_t)();

syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name);
#define vu_syscall_handler(s, n) (*(vu_syscall_handler_pointer(s, #n)))

#if __WORDSIZE == 32
#define vu_stat stat64
#else
#define vu_stat stat
#endif

#define VU_SYSNAME(name, syscall) vu_ ## name ## _ ## syscall
#define VU_PROTOTYPES(name) \
	\
int VU_SYSNAME(name, lstat) (char *pathname, struct vu_stat *buf, int flags, int sfd, void *private); \
int VU_SYSNAME(name, access) (char *path, int mode, int flags); \
ssize_t VU_SYSNAME(name, readlink) (char *path, char *buf, size_t bufsiz); \
int VU_SYSNAME(name, open) (const char *pathname, int flags, mode_t mode, void **private); \
int VU_SYSNAME(name, close) (int fd, void *private); \
ssize_t VU_SYSNAME(name, read) (int fd, void *buf, size_t count, void *private); \
ssize_t VU_SYSNAME(name, write)(int fd, const void *buf, size_t count, void *private); \
int VU_SYSNAME(name, getdents64) (unsigned int fd, struct dirent64 *dirp, unsigned int count, void *private); \
off_t VU_SYSNAME(name, lseek) (int fd, off_t offset, int whence, void *private); \
int VU_SYSNAME(name, unlink) (const char *pathname); \
int VU_SYSNAME(name, mkdir) (const char *pathname, mode_t mode); \
int VU_SYSNAME(name, rmdir) (const char *pathname); \
int VU_SYSNAME(name, chmod) (const char *pathname, mode_t mode, int fd, void *private); \
int VU_SYSNAME(name, lchown) (const char *pathname, uid_t owner, gid_t group, int fd, void *private); \
int VU_SYSNAME(name, utimensat) (int dirfd, const char *pathname, \
		const struct timespec times[2], int flags, int fd, void *private); \
int VU_SYSNAME(name, symlink) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, link) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, rename) (const char *target, const char *linkpath, int flags); \


#define CHECKMODULE 0        // Module name
#define CHECKPATH 1          // Path
#define CHECKSOCKET 2        // Address Family
#define CHECKCHRDEVICE 3     // chr device maj/min
#define CHECKBLKDEVICE 4     // blk device
#define CHECKSC 5            // Syscall #

#define SET_EPOCH 1
#define NEGATIVE_MOUNT ((confirmfun_t)1)

typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct hashtable_obj_t *ht);

struct hashtable_obj_t *ht_tab_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data);

struct hashtable_obj_t *ht_tab_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *private_data);

void ht_tab_invalidate(struct hashtable_obj_t *hte);
int ht_tab_del(struct hashtable_obj_t *hte);

#if __WORDSIZE == 32
#define __VU_vu_lstat __VU_lstat64
#define vu_stat stat64
#define vu_lstat lstat64
#else
#define vu_stat stat
#define vu_lstat lstat
#endif

#define KERN_SOH  "\001"    /* ASCII Start Of Header */
#define KERN_EMERG KERN_SOH "0"  /* system is unusable */
#define KERN_ALERT KERN_SOH "1"  /* action must be taken immediately */
#define KERN_CRIT KERN_SOH "2"  /* critical conditions */
#define KERN_ERR  KERN_SOH "3"  /* error conditions */
#define KERN_WARNING  KERN_SOH "4"  /* warning conditions */
#define KERN_NOTICE KERN_SOH "5"  /* normal but significant condition */
#define KERN_INFO KERN_SOH "6"  /* informational */
#define KERN_DEBUG KERN_SOH "7" /*debug-level messages */

int vprintk(const char *fmt, va_list ap);
int printk(const char *fmt, ...);

int _printkdebug(int index, const char *fmt, ...);
#define printkdebug(tag, fmt, ...) \
	if (__builtin_expect(debugmask & (1ULL << DEBUG_TAG2INDEX_##tag), 0)) \
_printkdebug(DEBUG_TAG2INDEX_##tag, "%s:%d " fmt "\n", \
		basename(__FILE__), __LINE__, ##__VA_ARGS__)

#define DEBUG_TAG2INDEX_A 1
#define DEBUG_TAG2INDEX_B 2
#define DEBUG_TAG2INDEX_C 3
#define DEBUG_TAG2INDEX_D 4
#define DEBUG_TAG2INDEX_E 5
#define DEBUG_TAG2INDEX_F 6
#define DEBUG_TAG2INDEX_G 7
#define DEBUG_TAG2INDEX_H 8
#define DEBUG_TAG2INDEX_I 9
#define DEBUG_TAG2INDEX_J 10
#define DEBUG_TAG2INDEX_K 11
#define DEBUG_TAG2INDEX_L 12
#define DEBUG_TAG2INDEX_M 13
#define DEBUG_TAG2INDEX_N 14
#define DEBUG_TAG2INDEX_O 15
#define DEBUG_TAG2INDEX_P 16
#define DEBUG_TAG2INDEX_Q 17
#define DEBUG_TAG2INDEX_R 18
#define DEBUG_TAG2INDEX_S 19
#define DEBUG_TAG2INDEX_T 20
#define DEBUG_TAG2INDEX_U 21
#define DEBUG_TAG2INDEX_V 22
#define DEBUG_TAG2INDEX_W 23
#define DEBUG_TAG2INDEX_X 24
#define DEBUG_TAG2INDEX_Y 25
#define DEBUG_TAG2INDEX_Z 26

#endif
