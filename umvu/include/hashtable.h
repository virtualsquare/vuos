#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdio.h>
#include <epoch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

/* This hashtable data structure has a central role in umvu.
 * A module adds a hashtable entry to start a virtualization.
 * e.g. if it adds a CHECKPATH element it means that the module
 * virtualizes a subtree of the file system, if it adds
 * a CHECKSOCKET it virtualizes an address family */
struct vuht_entry_t;
struct vu_service_t;

#define PSEUDO_CHECK 0x80
#define CHECKMODULE 0        // Module name
#define CHECKPATH 1          // Path
#define CHECKSOCKET 2        // Address Family
#define CHECKCHRDEVICE 3     // chr device maj/min
#define CHECKBLKDEVICE 4     // blk device
#define CHECKSC 5            // Syscall #
#define CHECKIOCTL 6         // ioctl request
#define CHECKBINFMT 7        // Binfmt search
#define CHECKFSALIAS 8       // FSAlias (just a string->string matching) */
#define NCHECKS 9
#define CHECKFSTYPE (PSEUDO_CHECK | CHECKMODULE)
#define CHECKPATHEXACT (PSEUDO_CHECK | CHECKPATH)

#define SET_EPOCH 1
#define NEGATIVE_MOUNT ((confirmfun_t)1)

/* hashtable elements may have exception. when a confirm function
	 is defined (as an argument adding the hashtable element) that
	 confirm function is called prior to confirm each match */
typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht);

/* add an element to the hashtable */
/* confirmfun is a cleanup function for CHECKMODULE */
struct vuht_entry_t *vuht_add(uint8_t type, const void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data, int permanent);

/* add a path element to the hashtable: path elements have more
 * arguments (to create a virtual mount-table */
struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *private_data);

/* del takes the element out from the data structure.... */
/* supported flags: MNT_FORCE MNT_DETACH (both provide
	 immediate detach and lazy delete) */
int vuht_del(struct vuht_entry_t *hte, int umountflags);

/* pick searches an entry in this hashtable.
	 pick and drop respectively increment/decrement the usage count
	 of the hashtable element to check if it is in use and to implemented
	 delayed delection */
struct vuht_entry_t *vuht_pick(uint8_t type, void *arg, struct stat *st, int setepoch);
void vuht_pick_again(struct vuht_entry_t *hte);
void vuht_drop(struct vuht_entry_t *hte);

void forall_vuht_do(uint8_t type,
		void (*fun)(struct vuht_entry_t *ht, void *arg),
		void *arg);

/* write the mount table in f.
	 It is in the format of /proc/mounts or /etc/mtab */
void vuht_get_mtab(FILE *f);

/* return the object i.e. the key of hte */
const void *vuht_get_obj(struct vuht_entry_t *hte);

/* modules get the relative path to the mountpoint
	 this function converts paths to paths-for-modules (mpaths) */
const char *vuht_path2mpath(struct vuht_entry_t *hte, const char *path);

/* each hashtable entry has a private data field */
void *vuht_get_private_data(struct vuht_entry_t *hte);
void vuht_set_private_data(struct vuht_entry_t *hte, void *private_data);

/* set the cleanup function for modules */
void vuht_set_service_cleanupfun(struct vuht_entry_t *hte, confirmfun_t cleanup_fun);

/* change the epoch of a hashtable entry to the current epoch (it this useful? )*/
// void vuht_renew(struct vuht_entry_t *hte);
//char *vuht_get_servicename(struct vuht_entry_t *hte);
struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte);
unsigned long vuht_get_mountflags(struct vuht_entry_t *hte);
epoch_t vuht_get_vepoch(struct vuht_entry_t *hte);
int vuht_get_count(struct vuht_entry_t *hte);
int vuht_get_objlen(struct vuht_entry_t *hte);

void vuht_terminate();
#endif
