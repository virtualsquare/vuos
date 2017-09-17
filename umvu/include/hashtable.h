#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdio.h>
#include <epoch.h>
#include <sys/types.h>
#include <sys/stat.h>

struct vuht_entry_t;
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

typedef int (*confirmfun_t)(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht);

struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data);

struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *private_data);

void vuht_invalidate(struct vuht_entry_t *hte);
int vuht_del(struct vuht_entry_t *hte);

struct vuht_entry_t *ht_check(uint8_t type, void *arg, struct stat *st, int setepoch);

void forall_vuht_do(uint8_t type, 
		void (*fun)(struct vuht_entry_t *ht, void *arg),
		void *arg);

void vuht_get_mtab(FILE *f);

void *ht_get_private_data(struct vuht_entry_t *hte);
void ht_set_private_data(struct vuht_entry_t *hte, void *private_data);

struct vuht_entry_t *ht_search(uint8_t type, void *arg, int objlen,
		struct vu_service_t *service);

void ht_renew(struct vuht_entry_t *hte);
char *ht_get_servicename(struct vuht_entry_t *hte);
struct vu_service_t *ht_get_service(struct vuht_entry_t *hte);
unsigned long ht_get_mountflags(struct vuht_entry_t *hte);
epoch_t ht_get_vepoch(struct vuht_entry_t *hte);
void ht_count_plus1(struct vuht_entry_t *hte);
void ht_count_minus1(struct vuht_entry_t *hte);
int ht_get_count(struct vuht_entry_t *hte);

void ht_terminate();
#endif
