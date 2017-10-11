#ifndef VUMODULE_H
#define VUMODULE_H
#include <stdint.h>
#include <stdarg.h>

struct vu_service_t;
struct vuht_entry_t;

struct vu_module_t {
  char *name;
  char *description;
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
int VU_SYSNAME(name, lstat) (char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate); \
int VU_SYSNAME(name, access) (char *path, int mode, int flags); \
ssize_t VU_SYSNAME(name, readlink) (char *path, char *buf, size_t bufsiz); \
int VU_SYSNAME(name, open) (const char *pathname, int flags, mode_t mode, void **fdprivate); \
int VU_SYSNAME(name, close) (int fd, void *fdprivate); \
ssize_t VU_SYSNAME(name, read) (int fd, void *buf, size_t count, void *fdprivate); \
ssize_t VU_SYSNAME(name, write)(int fd, const void *buf, size_t count, void *fdprivate); \
int VU_SYSNAME(name, getdents64) (unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate); \
off_t VU_SYSNAME(name, lseek) (int fd, off_t offset, int whence, void *fdprivate); \
int VU_SYSNAME(name, unlink) (const char *pathname); \
int VU_SYSNAME(name, truncate) (const char *path, off_t length, int fd, void *fdprivate); \
int VU_SYSNAME(name, mkdir) (const char *pathname, mode_t mode); \
int VU_SYSNAME(name, rmdir) (const char *pathname); \
int VU_SYSNAME(name, chmod) (const char *pathname, mode_t mode, int fd, void *fdprivate); \
int VU_SYSNAME(name, lchown) (const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate); \
int VU_SYSNAME(name, utimensat) (int dirfd, const char *pathname, \
		const struct timespec times[2], int flags, int fd, void *fdprivate); \
int VU_SYSNAME(name, symlink) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, link) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, rename) (const char *target, const char *linkpath, int flags); \
int VU_SYSNAME(name, mount) (const char *source, const char *target, \
		const char *filesystemtype, unsigned long mountflags, \
		const void *data); \
int VU_SYSNAME(name, umount2) (const char *target, int flags); \
ssize_t VU_SYSNAME(name, lgetxattr) (const char *path, const char *name, \
		void *value, size_t size, int fd, void *fdprivate); \
int VU_SYSNAME(name, lsetxattr) (const char *path, const char *name, \
		const void *value, size_t size, int flags, int fd, void *fdprivate); \
ssize_t VU_SYSNAME(name, llistxattr) (const char *path, \
		char *list, size_t size, int fd, void *fdprivate); \
int VU_SYSNAME(name, lremovexattr) (const char *path, const char *name, int fd, void *fdprivate); \



#define CHECKMODULE 0        // Module name
#define CHECKPATH 1          // Path
#define CHECKSOCKET 2        // Address Family
#define CHECKCHRDEVICE 3     // chr device maj/min
#define CHECKBLKDEVICE 4     // blk device
#define CHECKSC 5            // Syscall #
#define CHECKIOCTL 6         // ioctl request
#define CHECKBINFMT 7        // Binfmt search

#define SET_EPOCH 1
#define NEGATIVE_MOUNT ((confirmfun_t)1)

typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht);

struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *ht_private_data, int permanent);

struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *ht_private_data);

struct vuht_entry_t *vu_mod_getht(void);
struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte);
__attribute__((always_inline))
  static inline syscall_t vu_mod_getservice(void) {
		return vuht_get_service(vu_mod_getht());
  }

void *vuht_get_private_data(struct vuht_entry_t *hte);
void vuht_set_private_data(struct vuht_entry_t *hte, void *ht_private_data);

__attribute__((always_inline))
	static inline void *vu_get_ht_private_data(void) {
		return vuht_get_private_data(vu_mod_getht());
	}

__attribute__((always_inline))
	static inline void vu_set_ht_private_data(void *ht_private_data) {
		vuht_set_private_data(vu_mod_getht(), ht_private_data);
	}

void vuht_invalidate(struct vuht_entry_t *hte);
int vuht_del(struct vuht_entry_t *hte, int delayed);

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

extern uint64_t debugmask;
extern __thread uint64_t tdebugmask;

int _printkdebug(int index, const char *fmt, ...);
#define printkdebug(tag, fmt, ...) \
  if (__builtin_expect((debugmask | tdebugmask) & (1ULL << DEBUG_TAG2INDEX_##tag), 0)) \
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
