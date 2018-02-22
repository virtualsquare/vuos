#ifndef VUMODULE_H
#define VUMODULE_H
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/epoll.h>


struct vu_service_t;
struct vuht_entry_t;

/**vu_lsmod prints this infos.*/
struct vu_module_t {
  char *name;
  char *description;
};

typedef long (*syscall_t)();
extern uint16_t vu_arch_table[];

syscall_t *vu_syscall_handler_pointer(struct vu_service_t *service, char *name);
/**If the implementation of some syscall (read for example) is not changed by the module, it should be decleared with this macro:
		vu_syscall_handler(s,read) = read; //this is an example
	This informs the hypervisor to use the normal implementation of the call istead of that given by the module.*/
#define vu_syscall_handler(s, n) (*(vu_syscall_handler_pointer(s, #n)))

#if __WORDSIZE == 32
#define vu_stat stat64
#else
#define vu_stat stat
#endif

/**There isn't a definition for each syscalll: umvu unifies the management of some system calls because
	the pathnames given by the hypervisor are always absolute (canonicalized).
	For example lstat function is used for lstat stat fstat fstatat.

	This definitions allow to change the behavior and implementation fo the system call achieving the virtualization.
	There are also init and fini module functions called at the module's load or unload respectively.*/
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
int VU_SYSNAME(name, getdents64) (unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate); \
off_t VU_SYSNAME(name, lseek) (int fd, off_t offset, int whence, void *fdprivate); \
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

//a comment i required
typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht);

/**Each module must register its working domain, i.e. subtree of the file system, the system calls,
	address families it defines.
	vuht_add and vuht_pathadd allow to add hast table elements (generic objects or pathnames respectively)
	that will be used by the hypervisor to referfer to that module.
	Choosing the kind of syscall management is no more then a search of the right hash table element
	inserted by the right module.*/
/**ht_private_data can be used to store information useful for the module.*/
struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *ht_private_data, int permanent);

/**More specific for mount syscall because it generates mount tab.*/
struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *ht_private_data);

/**The module can access to the hash table element choosen by the hypervisor.
	Consider that vu_insmod add a hash table element with this parameter:

	vuht_add(CHECKMODULE, modname, strlen(modname), service,NULL, NULL, permanent);

	so it can be choosen too by the tracer. */
struct vuht_entry_t *vu_mod_getht(void);

struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte);
__attribute__((always_inline))
  static inline syscall_t vu_mod_getservice(void) {  // shouldn't return a struct vu_service_t *?
		return vuht_get_service(vu_mod_getht());  
  }

/**Private information of the module, can be used to store any kind of variable that the module will need later. */
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

typedef enum mod_inheritance_state_t {
  MOD_INH_CLONE,	// a process is doing a clone
  MOD_INH_START,	// a tracer has started
  MOD_INH_EXEC,		// a process is doing an execve
  MOD_INH_TERMINATE	// a process has ended
} mod_inheritance_state_t;

struct mod_inheritance_exec_arg {
	uid_t exec_uid;
	gid_t exec_gid;
};

/**Allows to register functions with a specific behavior depending on (switch case) the mod_inheritance_state_t.
	The module can,in this way, perform actions during  a process clone,start,exec,terminate.
	(The registered functions will be called in that sistuations.) */
typedef void *(*mod_inheritance_upcall_t)(mod_inheritance_state_t, void *);
void mod_inheritance_upcall_register(mod_inheritance_upcall_t upcall);
void mod_inheritance_upcall_deregister(mod_inheritance_upcall_t upcall);

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
