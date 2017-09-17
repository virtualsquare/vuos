#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdio.h>
#include <epoch.h>
#include <sys/types.h>
#include <sys/stat.h>

struct hashtable_obj_t;
struct vu_service_t;

#define PSEUDO_CHECK 0x80
#define CHECKMODULE 0        // Module name 
#define CHECKPATH 1          // Path
#define CHECKSOCKET 2        // Address Family
#define CHECKCHRDEVICE 3     // chr device maj/min
#define CHECKBLKDEVICE 4     // blk device
#define CHECKSC 5            // Syscall #
#define CHECKBINFMT 6        // Binfmt search
#define CHECKFSALIAS 7       // FSAlias (just a string->string matching) */
#define NCHECKS 8
#define CHECKFSTYPE (PSEUDO_CHECK | CHECKMODULE)
#define CHECKPATHEXACT (PSEUDO_CHECK | CHECKPATH)

#define SET_EPOCH 1
#define NEGATIVE_MOUNT ((confirmfun_t)1)
//#define HT_ERR ((hashtable_obj_t *)1)

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

struct hashtable_obj_t *ht_check(uint8_t type, void *arg, struct stat *st, int setepoch);

void forall_ht_tab_do(uint8_t type, 
		void (*fun)(struct hashtable_obj_t *ht, void *arg),
		void *arg);

void ht_tab_get_mtab(FILE *f);

void *ht_get_private_data(struct hashtable_obj_t *hte);
void ht_set_private_data(struct hashtable_obj_t *hte, void *private_data);

struct hashtable_obj_t *ht_search(uint8_t type, void *arg, int objlen,
		struct vu_service_t *service);

void ht_renew(struct hashtable_obj_t *hte);
char *ht_get_servicename(struct hashtable_obj_t *hte);
struct vu_service_t *ht_get_service(struct hashtable_obj_t *hte);
unsigned long ht_get_mountflags(struct hashtable_obj_t *hte);
epoch_t ht_get_vepoch(struct hashtable_obj_t *hte);
void ht_count_plus1(struct hashtable_obj_t *hte);
void ht_count_minus1(struct hashtable_obj_t *hte);
int ht_get_count(struct hashtable_obj_t *hte);

void ht_terminate();
#endif
