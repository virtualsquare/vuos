#ifndef VUMODULE_H
#define VUMODULE_H
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/capability.h>

/* header file for VUOS module implementation */

/* a module must define a struct vu_module_t global non static variable
	 named vu_module*/
/* if the name of the module (vu_module.name) is xxx:
 *   the module constructor is:
 *       void *vu_xxx_init(void)
 *   the destructor is:
 *       int vu_xxx_fini(void *private_data);
 *   system call handlers can be defined in two ways:
 *       by defining a function whose name has the prefix vu_xxx_ (like vu_xxx_open, vu_xxx_write)
 *       using the macro vu_syscall_handler in the constructor
 *       (the former way is used to define an implementation of the system call, the latter way
 *        is preferred to use an existing function (e.g. the system call implementation by glibc) */

/* when a module is loaded, it defines a service. A service can be seen as a descriptor for a module. */
struct vu_service_t;
struct vuht_entry_t;

struct vu_module_t {
  char *name;
  char *description;
};

typedef long (*syscall_t)();
extern uint16_t vu_arch_table[];
extern char *mountflag_strings[32];

syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name);
#define vu_syscall_handler(s, n) (*(vu_syscall_handler_pointer(s, #n)))

#if __WORDSIZE == 32
#define vu_stat stat64
#else
#define vu_stat stat
#endif

/* the macro VU_PROTOTYPES gets the name of the module as its argument. VU_PROTOTYPES
	 defines the signature of all possible module define functions that VUOS core can call.
	 VU_PROTOTYPES is for type checking */

/* deallocation of data-structures must be in the cleanup function.
	 umount should only delete the entry/entries from the hash table (vuht_del) */

#define VU_SYSNAME(name, syscall) vu_ ## name ## _ ## syscall
#define VU_PROTOTYPES(name) \
	\
void * VU_SYSNAME(name, init) (void); \
int VU_SYSNAME(name, fini) (void *); \
int VU_SYSNAME(name, lstat) (char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate); \
int VU_SYSNAME(name, access) (char *path, int mode, int flags); \
ssize_t VU_SYSNAME(name, readlink) (char *path, char *buf, size_t bufsiz); \
int VU_SYSNAME(name, open) (const char *pathname, int flags, mode_t mode, void **fdprivate); \
int VU_SYSNAME(name, close) (int fd, void *fdprivate); \
ssize_t VU_SYSNAME(name, read) (int fd, void *buf, size_t count, void *fdprivate); \
ssize_t VU_SYSNAME(name, write)(int fd, const void *buf, size_t count, void *fdprivate); \
ssize_t VU_SYSNAME(name, pread64) (int fd, void *buf, size_t count, off_t offset, int flags, void *fdprivate); \
ssize_t VU_SYSNAME(name, pwrite64)(int fd, const void *buf, size_t count, off_t offset, int flags, void *fdprivate); \
int VU_SYSNAME(name, getdents64) (unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate); \
off_t VU_SYSNAME(name, lseek) (int fd, off_t offset, int whence, void *fdprivate); \
int VU_SYSNAME(name, ioctl) (int fd, unsigned long request, void *buf, uintptr_t addr, void *fdprivate); \
int VU_SYSNAME(name, unlink) (const char *pathname); \
int VU_SYSNAME(name, truncate) (const char *path, off_t length, int fd, void *fdprivate); \
int VU_SYSNAME(name, mkdir) (const char *pathname, mode_t mode); \
int VU_SYSNAME(name, mknod) (const char *pathname, mode_t mode, dev_t dev); \
int VU_SYSNAME(name, rmdir) (const char *pathname); \
int VU_SYSNAME(name, chmod) (const char *pathname, mode_t mode, int fd, void *fdprivate); \
int VU_SYSNAME(name, lchown) (const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate); \
int VU_SYSNAME(name, utimensat) (int dirfd, const char *pathname, \
		const struct timespec times[2], int flags, int fd, void *fdprivate); \
int VU_SYSNAME(name, symlink) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, link) (const char *target, const char *linkpath); \
int VU_SYSNAME(name, rename) (const char *target, const char *linkpath, int flags); \
int VU_SYSNAME(name, statfs) (const char *pathname, struct statfs *buf, int fd, void *fdprivate); \
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
int VU_SYSNAME(name, epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event, void *fdprivate); \
int VU_SYSNAME(name, getresfuid) (uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid, void *private); \
int VU_SYSNAME(name, getresfgid) (gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid, void *private); \
int VU_SYSNAME(name, setresfuid) (uid_t ruid, uid_t euid, uid_t suid, uid_t fsuid, void *private); \
int VU_SYSNAME(name, setresfgid) (gid_t rgid, gid_t egid, gid_t sgid, gid_t fsgid, void *private); \
int VU_SYSNAME(name, socket) (int domain, int type, int protocol, void **fdprivate); \
int VU_SYSNAME(name, bind) (int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate); \
int VU_SYSNAME(name, connect) (int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate); \
int VU_SYSNAME(name, listen) (int sockfd, int backlog, void *fdprivate); \
int VU_SYSNAME(name, accept4) (int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags, void *fdprivate); \
int VU_SYSNAME(name, getsockname) (int sockfd, struct sockaddr *addr, socklen_t *addrlen, void *fdprivate); \
int VU_SYSNAME(name, getpeername) (int sockfd, struct sockaddr *addr, socklen_t *addrlen, void *fdprivate); \
ssize_t VU_SYSNAME(name, sendto) (int sockfd, const void *buf, size_t len, int flags, \
		const struct sockaddr *dest_addr, socklen_t addrlen, \
		void *msg_control, size_t msg_controllen, void *fdprivate); \
ssize_t VU_SYSNAME(name, recvfrom) (int sockfd, void *buf, size_t len, int flags, \
		struct sockaddr *src_addr, socklen_t *addrlen, \
		void *msg_control, size_t *msg_controllen, void *fdprivate); \
int VU_SYSNAME(name, getsockopt) (int sockfd, int level, int optname, \
		void *optval, socklen_t *optlen, void *fdprivate); \
int VU_SYSNAME(name, setsockopt) (int sockfd, int level, int optname, \
		const void *optval, socklen_t optlen, void *fdprivate); \
int VU_SYSNAME(name, capget) (cap_user_header_t hdrp, cap_user_data_t datap); \
int VU_SYSNAME(name, capset) (cap_user_header_t hdrp, const cap_user_data_t datap); \
\
void VU_SYSNAME(name, cleanup) (uint8_t type, void *arg, int arglen, \
    struct vuht_entry_t *ht); \

/* HASH TABLE management functions */

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

struct vuht_entry_t *vuht_add(uint8_t type, const void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *ht_private_data, int permanent);

struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *ht_private_data);

#define BINFMTBUFLEN 128
#define BINFMTLINELEN 1920
#define BINFMT_PRESERVE_ARGV0 0x1
#define BINFMT_OPEN_BINARY    0x2
#define BINFMT_CREDENTIALS    0x4

struct binfmt_req_t {
  char *path;
  char filehead[BINFMTBUFLEN + 2];
  int fileheadlen;
  int flags;
};

/* mainly for modules' threads */
struct vuht_entry_t *vu_mod_getht(void);
void vu_mod_setht(struct vuht_entry_t *ht);
pid_t vu_mod_gettid();
void vu_mod_peek_str(void *addr, void *buf, size_t datalen);
char *vu_mod_peekdup_path(void *addr);
void vu_mod_peek_data(void *addr, void *buf, size_t datalen);
void vu_mod_poke_data(void *addr, void *buf, size_t datalen);

mode_t vu_mod_getumask(void);
mode_t vu_mod_getmode(void);

struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte);
__attribute__((always_inline))
	static inline struct vu_service_t * vu_mod_getservice(void) {
		return vuht_get_service(vu_mod_getht());
	}

const void *vuht_get_obj(struct vuht_entry_t *hte);
int vuht_get_objlen(struct vuht_entry_t *hte);
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

/* supported flags: MNT_FORCE MNT_DETACH (both provide
	 immediate detach and lazy delete) */
int vuht_del(struct vuht_entry_t *hte, int umountflags);

/* load submodules */
void *vu_mod_dlopen(const char *modname, int flags);

/* inheritance management, define an upcall function to
	 track process creation, exec, and termination */
/* MOD_INH_CLONE happens before process creation,
	 MOD_INH_START is an event of the new tracing thread.
	 The return value of clone is delivered as a parameter to start */
typedef enum mod_inheritance_state_t {
	MOD_INH_CLONE,
	MOD_INH_START,
	MOD_INH_EXEC,
	MOD_INH_TERMINATE
} mod_inheritance_state_t;

struct mod_inheritance_exec_arg {
	uid_t exec_uid;
	gid_t exec_gid;
};

typedef void *(*mod_inheritance_upcall_t)(mod_inheritance_state_t, void *);
void mod_inheritance_upcall_register(mod_inheritance_upcall_t upcall);
void mod_inheritance_upcall_deregister(mod_inheritance_upcall_t upcall);

/* stat must be implemented using 64bit data structures
	 even if VUOS is running on a 32bit architecture.
	 always use vu_stat/vu_lstat when writing module code */
#if __WORDSIZE == 32
#define __VU_vu_lstat __VU_lstat64
#define vu_stat stat64
#define vu_lstat lstat64
#else
#define vu_stat stat
#define vu_lstat lstat
#endif

/* log/debug facilities */
#define KERN_SOH  "\001"    /* ASCII Start Of Header */
#define KERN_EMERG KERN_SOH "0"  /* system is unusable */
#define KERN_ALERT KERN_SOH "1"  /* action must be taken immediately */
#define KERN_CRIT KERN_SOH "2"  /* critical conditions */
#define KERN_ERR  KERN_SOH "3"  /* error conditions */
#define KERN_WARNING  KERN_SOH "4"  /* warning conditions */
#define KERN_NOTICE KERN_SOH "5"  /* normal but significant condition */
#define KERN_INFO KERN_SOH "6"  /* informational */
#define KERN_DEBUG KERN_SOH "7" /*debug-level messages */

void _debug_set_name(int index, const char *s);
void debug_get_name(char tag, char *buf, size_t bufsize);

#define debug_set_name(tag, s) \
  _debug_set_name(DEBUG_TAG2INDEX_##tag, "" s)

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
