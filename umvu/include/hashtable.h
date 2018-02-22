#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdio.h>
#include <epoch.h>
#include <sys/types.h>
#include <sys/stat.h>

struct vuht_entry_t;
struct vu_service_t;

#define PSEUDO_CHECK 0x80
/**types for the obj filed. The object can be: a module name, a path, ... */
#define CHECKMODULE 0        // Module name 
#define CHECKPATH 1          // Path
#define CHECKSOCKET 2        // Address Family
#define CHECKCHRDEVICE 3     // chr device maj/min
#define CHECKBLKDEVICE 4     // blk device
#define CHECKSC 5            // Syscall #
#define CHECKIOCTL 6         // ioctl request 
#define CHECKBINFMT 7        // Binfmt search
#define CHECKFSALIAS 8       // FSAlias (just a string->string matching) 
#define NCHECKS 9
#define CHECKFSTYPE (PSEUDO_CHECK | CHECKMODULE)
#define CHECKPATHEXACT (PSEUDO_CHECK | CHECKPATH)

#define SET_EPOCH 1
#define NEGATIVE_MOUNT ((confirmfun_t)1)

typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht);

struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data, int permanent);

/**This function is similar to vuht_add, but it's specific for generating the mount tab line (see /proc/mounts) according to the mountflags.*/
struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *private_data);

/* del takes the element out from the data structure.... */
int vuht_del(struct vuht_entry_t *hte, int delayed);
///* free dealloc memory, vuht_free must follow a vuht_del */
//int vuht_free(struct vuht_entry_t *hte);

/** type and arg guide the search throght the table.*/
struct vuht_entry_t *vuht_pick(uint8_t type, void *arg, struct stat *st, int setepoch);

/**Recording the usage count of the hash table element: every time someone picks it add 1, when it's not used anymore by that one sub 1. */
void vuht_pick_again(struct vuht_entry_t *hte);
void vuht_drop(struct vuht_entry_t *hte);

void forall_vuht_do(uint8_t type, 
		void (*fun)(struct vuht_entry_t *ht, void *arg),
		void *arg);

void vuht_get_mtab(FILE *f);

void *vuht_get_private_data(struct vuht_entry_t *hte);
void vuht_set_private_data(struct vuht_entry_t *hte, void *private_data);

#if 0
struct vuht_entry_t *vuht_search(uint8_t type, void *arg, int objlen,
		struct vu_service_t *service);
#endif

void vuht_renew(struct vuht_entry_t *hte);
//char *vuht_get_servicename(struct vuht_entry_t *hte);
struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte);
unsigned long vuht_get_mountflags(struct vuht_entry_t *hte);
epoch_t vuht_get_vepoch(struct vuht_entry_t *hte);
int vuht_get_count(struct vuht_entry_t *hte);

void vuht_terminate();
#endif
