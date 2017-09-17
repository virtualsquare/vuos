#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mount.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <vu_log.h>
#include <linux_32_64.h>
#include <hashtable.h>
#include <service.h>
#include <carrot.h>

/*Hashtable object definition*/
/* vuht_entry_t:
	 @obj: hash key
	 @mtabline: mount tab line
	 @type: type
	 @trailingnumbers: boolean, match pathnames with trailing numbers
	 @invalid: boolean, the element is logically deleted
	 @service: service associated to this item
	 @service_hte: hte of the service associated to this item
	 @private_data: opaque container for module data
	 @objlen: len of the hash key
	 @hashsum: hash sum for quick negative matching
	 @count: usage count
	 @confirmfun: confirmation function for exceptions
	 @prev/next/pprevhash,nexthash: addresses for list linking
 */
struct vuht_entry_t {
	void *obj;
	char *mtabline;
	unsigned long mountflags;
	epoch_t timestamp;
	uint8_t type;
	uint8_t trailingnumbers;
	uint8_t invalid;
	struct vu_service_t *service;
	struct vuht_entry_t *service_hte;
	void *private_data;
	int objlen;
	long hashsum;
	int count;
	/* confirmfun_t */
	confirmfun_t confirmfun;
	struct vuht_entry_t *prev, *next, **pprevhash, *nexthash;
};

/* it must be a power of two (masks are used instead of modulo) */
#define VU_HASHTABLE_SIZE 512
#define VU_HASHTABLE_MASK (VU_HASHTABLE_SIZE-1)

/* ReadWrite lock to access the Hashtable */
static pthread_rwlock_t ht_rwlock = PTHREAD_RWLOCK_INITIALIZER;
/* this is THE hash */
static struct vuht_entry_t *ht_hash[VU_HASHTABLE_SIZE];

/* null tags have separate a separate list */
static struct vuht_entry_t *ht_hash0[NCHECKS];

/* heads of the list of hash entries of the same type */
static struct vuht_entry_t *ht_head[NCHECKS];

/* /free of vuht_entry_t */
static inline struct vuht_entry_t *vuht_alloc() {
	struct vuht_entry_t *rv = malloc(sizeof (struct vuht_entry_t));
	fatal(rv);
	return rv;
}

static inline void vuht_free(struct vuht_entry_t *ht) {
	free(ht->obj);
	if (ht->mtabline)
		free(ht->mtabline);
	free(ht);
}

/* hash function */
/* hash sum and mod are separate functions:
	 hash sums are used to quickly eliminate false positives,
	 intermediate results can be completed during the scan */
static inline int hashmod(long hashsum)
{
	return hashsum & VU_HASHTABLE_MASK;
}

/* djb2 hash function */
static inline long hashadd(long prevhash, char c)
{
	return (((prevhash << 5) + prevhash) + c);
}

static inline long hashsum(uint8_t type, const char *c, int len)
{
	long hash = type;
	int i;

	for (i = 0; i < len; i++, c++)
		hash = hashadd(hash, *c);
	return hash;
}

/* true if there are only trailing numbers (and there is at least one) */
/* View-OS permits "mount" of things like /dev/hda[0-9]* */
static inline int trailnum(char *s)
{
	/* "at least one" the first element needs a special case.
     performance:  >'9' is the most frequent case, <'0' are quite rare
     in pathnames, the end of string is more common */
	int nonzero = 0;

	if (*s > '9' || *s == 0 || *s < '0')
		return 0;
	nonzero |= *s - '0';
	for (s++; *s; s++) {
		if (*s > '9' || *s < '0')
			return 0;
		nonzero |= *s - '0';
	}
	return nonzero;
}

/* during the scan: search in the hash table if this returns 1 */
static int ht_scan_stop(uint8_t type, char *objc, int len, int exact)
{
	switch (type) {
		case CHECKPATH:
			return (
					*objc == 0 /* this is the end of a string */
					||
					(!exact           /* or when subtring match are allowed */
					 && (*objc == '/' /* test the match if the current char is '/' */
						 /* or if there are trailing numbers e.g. /dev/hda1, hda2 etc */
						 || trailnum(objc))));
		case CHECKBINFMT:
			return (*objc == 0 /* this is the end of a string */
					||
					(!exact /* or when subtring match are allowed */
					 &&
					 *objc == '/')); /* test the match if the current char is '/' */
		case CHECKSOCKET:
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
		case CHECKSC: /* array of int, or null keys */
			return ((len % sizeof(int)) == 0);
		case CHECKFSALIAS: /* end of string */
			return (*objc == 0);
		case CHECKMODULE:
			if (exact)
				return (*objc == 0);
			else
				return 1; /* CHECKFSTYPE char by char */
		default:
			return 0;
																																			    }
}

/* terminate the scan */
static inline int ht_scan_terminate(uint8_t type, char *objc, int len,
		int objlen)
{
	switch (type) {
		case CHECKPATH:
		case CHECKBINFMT:
		case CHECKFSALIAS:
		case CHECKMODULE:
			return (*objc == 0);
		case CHECKSOCKET:
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
		case CHECKSC:
			return (len == objlen);
		default:
			return 0;
	}
}

struct confirm_arg {
	uint8_t type; 
	void *checkobj;
	int len; 
};

static int call_confirmfun(struct vuht_entry_t *ht, void *opaque) {
	confirmfun_t confirm = ht->confirmfun;
	if (confirm) {
		struct confirm_arg *args = opaque;
		epoch_t epoch = set_vepoch(ht->timestamp);
		int rv = confirm(args->type, args->checkobj, args->len, ht);
		set_vepoch(epoch);
		return rv;
	} else
		return 1;
}

static int has_exception(struct vuht_entry_t *ht) {
	return ht->confirmfun != NULL;
}

static struct vuht_entry_t *vuht_internal_search(uint8_t type, void *obj,
		int objlen, void *checkobj,
		int exact) {
	struct vuht_entry_t *rv = NULL;
	epoch_t tst = get_vepoch();
	char *objc = obj;
	long sum = type;
	long hash;
	struct carrot_t *carh = NULL;
	struct vuht_entry_t *ht;
	int len = 0;
	epoch_t e;

	pthread_rwlock_rdlock(&ht_rwlock);
	while (1) {
		if (ht_scan_stop(type, objc, len, exact)) {
			hash = hashmod(sum);
			ht = ht_hash[hash];
			ht=(len) ? ht_hash[hash] : ht_hash0[type];
			while (ht != NULL) {
				if (type == ht->type && sum == ht->hashsum &&
						memcmp(obj, ht->obj, len) == 0 &&
						(ht->trailingnumbers || !trailnum(objc)) &&
						(tst > ht->timestamp) &&
						(e = matching_epoch(ht->timestamp)) > 0 &&
						(ht->invalid == 0)) {
					/*carrot add*/
					if (ht->confirmfun == NEGATIVE_MOUNT)
						carh = carrot_delete(carh, ht->private_data);
					else
						carh = carrot_insert(carh, ht, e, has_exception);
				}
				ht = ht->nexthash;
			}
			if (ht_scan_terminate(type, objc, len, objlen))
				break;
		}
		sum = hashadd(sum, *objc);
		objc++;
		len++;
	}
	if (carh != NULL) {
		struct confirm_arg args = {
			.type = type,
			.checkobj = checkobj,
			.len = len
		};
		rv = carrot_check(carh, call_confirmfun, &args);
	}
	pthread_rwlock_unlock(&ht_rwlock);
	return rv;
}

static inline struct vuht_entry_t *vuht_pathsearch(uint8_t type, void *obj,
		int exact)
{
	return vuht_internal_search(type, obj, 0, obj, exact);
}

static inline struct vuht_entry_t *vuht_binfmtsearch(uint8_t type,
		struct binfmt_req_t *req, int exact)
{
	return vuht_internal_search(type, req->path, 0, req, exact);
}

static inline struct vuht_entry_t *vuht_search(uint8_t type, void *obj,
		int objlen, int exact)
{
	return vuht_internal_search(type, obj, objlen, obj, exact);
}

static struct vuht_entry_t *
internal_vuht_add(uint8_t type, const void *obj, int objlen,
		unsigned long mountflags, char *mtabline,
		struct vu_service_t *service, uint8_t trailingnumbers,
		confirmfun_t confirmfun, void *private_data)
{
	struct vuht_entry_t **hashhead;
	struct vuht_entry_t *new = vuht_alloc();
	/* create the entry and fill in the fields */
	fatal(new);
	new->obj = malloc(objlen);
	fatal(new->obj);
	memcpy(new->obj, obj, objlen);
	new->objlen = objlen;
	new->type = type;
	new->mountflags = mountflags;
	new->mtabline = mtabline;
	new->timestamp = update_epoch();
	new->trailingnumbers = trailingnumbers;
	new->invalid = 0;
	new->private_data = private_data;
	new->service = service;
	new->service_hte = NULL;
	new->confirmfun = confirmfun;
	new->count = 0;
	new->hashsum = hashsum(type, new->obj, new->objlen);
	pthread_rwlock_wrlock(&ht_rwlock);
	/* add it to the list of hash entry of this type */
	if (ht_head[type]) {
		new->next=ht_head[type]->next;
		new->prev=ht_head[type];
		new->next->prev=new;
		new->prev->next=new;
		ht_head[type]=new;
	} else
		ht_head[type]=new->next=new->prev=new;
	/* add it to the right hash collision list */
	if (objlen==0)
		hashhead=&ht_hash0[type];
	else
		hashhead=&ht_hash[hashmod(new->hashsum)];
	if (*hashhead)
		(*hashhead)->pprevhash=&(new->nexthash);
	new->nexthash=*hashhead;
	new->pprevhash=hashhead;
	*hashhead=new;
	pthread_rwlock_unlock(&ht_rwlock);
	return new;
} 

struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data) {
	return internal_vuht_add(type, obj, objlen, 0, NULL, service, 1,
			confirmfun, private_data);
}

static int permanent_mount(const char *opts)
{
	char *match;
	if (opts == NULL)
		return 0;
	return (match = strstr(opts, "permanent")) != NULL &&
		(match == opts || match[-1] == ',') &&
		(match[9] == '\0' || match[9] == ',');
}

struct vuht_entry_t *vuht_pathadd(uint8_t type, const char *source,
		const char *path, const char *fstype,
		unsigned long mountflags, const char *mountopts,
		struct vu_service_t *service,
		unsigned char trailingnumbers,
		confirmfun_t confirmfun, void *private_data) {
	char *mtabline;
	const char *addpath;
	struct vuht_entry_t *rv;
	if (source) {
		char opts[PATH_MAX];
		opts[0] = 0;
		if (mountflags & MS_REMOUNT)
			strncat(opts, "remount,", PATH_MAX);
		if (mountflags & MS_RDONLY)
			strncat(opts, "ro,", PATH_MAX);
		if (mountflags & MS_NOATIME)
			strncat(opts, "noatime,", PATH_MAX);
		if (mountflags & MS_NODEV)
			strncat(opts, "nodev,", PATH_MAX);
		if (mountflags & MS_NOEXEC)
			strncat(opts, "noexec,", PATH_MAX);
		if (mountflags & MS_NOSUID)
			strncat(opts, "nosuid,", PATH_MAX);
		if (mountflags & MS_SYNCHRONOUS)
			strncat(opts, "sync,", PATH_MAX);
		if (mountopts && *mountopts)
			strncat(opts, mountopts, PATH_MAX);
		else if (*opts)
			opts[strlen(opts) - 1] = 0;
		else
			strncat(opts, "rw", PATH_MAX);
		asprintf(&mtabline, "%s%s %s %s %s 0 %" PRIu64,
				(confirmfun == NEGATIVE_MOUNT) ? "-" : "", source, path,
				fstype, opts, get_epoch());
	} else
		mtabline = NULL;
	if (path[1] == '\0' && path[0] == '/')
		addpath = "";
	else
		addpath = path;
	rv = internal_vuht_add(type, addpath, strlen(addpath), mountflags,
			mtabline, service, trailingnumbers, confirmfun,
			private_data);
	if (permanent_mount(mountopts))
		rv->count++;
	if (rv == NULL && mtabline != NULL)
		free(mtabline);
	return rv;
}

/* delete an element from the hash table */
static void vuht_del_locked(struct vuht_entry_t *ht) {
	uint8_t type = ht->type;

	if (ht == ht_head[type]) {
		if (ht->next == ht)
			ht_head[type] = NULL;
		else
			ht_head[type] = ht->prev;
	}
	ht->prev->next = ht->next;
	ht->next->prev = ht->prev;
	*(ht->pprevhash) = ht->nexthash;
	if (ht->nexthash)
		ht->nexthash->pprevhash = ht->pprevhash;
	vuht_free(ht);
}

void vuht_invalidate(struct vuht_entry_t *ht) {
	if (ht)
		ht->invalid = 1;
}

int vuht_del(struct vuht_entry_t *ht) {
	if (ht) {
		pthread_rwlock_wrlock(&ht_rwlock);
		vuht_del_locked(ht);
		pthread_rwlock_unlock(&ht_rwlock);
		return 0;
	} else
		return -ENOENT;
}

/* searching API */
struct vuht_entry_t *ht_check(uint8_t type, void *arg, struct vu_stat *st, int setepoch) {
	struct vuht_entry_t *hte;

	switch (type) {
		case CHECKPATH:
			hte = vuht_pathsearch(type, arg, 0);
			if (hte != NULL && st != NULL) {
				if (__builtin_expect(S_ISCHR(st->st_mode), 0)) {
					hte = vuht_search(CHECKCHRDEVICE, &st->st_rdev,
							sizeof(dev_t), 0);
				} else if (__builtin_expect(S_ISBLK(st->st_mode), 0)) {
					hte = vuht_search(CHECKBLKDEVICE, &st->st_rdev,
							sizeof(dev_t), 0);
				}
			}
			break;
		case CHECKPATHEXACT:
			hte = vuht_pathsearch(CHECKPATH, arg, 1);
			break;
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
			hte = vuht_search(type, arg, sizeof(dev_t), 0);
			break;
		case CHECKSOCKET:
		case CHECKSC:
			hte = vuht_search(type, arg, sizeof(int), 0);
			break;
		case CHECKFSALIAS:
		case CHECKMODULE:
			hte = vuht_search(type, arg, 0, 1);
			break;
		case CHECKFSTYPE:
			hte = vuht_search(CHECKMODULE, arg, 0, 0);
			break;
		case CHECKBINFMT:
			hte = vuht_binfmtsearch(type, arg, 0);
			break;
		default:
			hte = NULL;
	}
	if (hte && setepoch)
		set_vepoch(hte->timestamp);
	return hte;
}

/* reverse scan of hash table elements, useful to close all files  */
static void forall_ht_terminate(uint8_t type)
{
	pthread_rwlock_rdlock(&ht_rwlock);
	if (ht_head[type]) {
		struct vuht_entry_t *scanht = ht_head[type];
		struct vuht_entry_t *next = scanht;
		do {
			scanht = next;
			if (scanht->invalid == 0) {
				/* if (scanht->service != NULL &&
						scanht->service->destructor != NULL)
					scanht->service->destructor(type, scanht); */
			}
			next = scanht->prev;
		} while (ht_head[type] != NULL && next != ht_head[type]);
	}
	pthread_rwlock_unlock(&ht_rwlock);
}

void forall_vuht_do(uint8_t type, 
		void (*fun)(struct vuht_entry_t *ht, void *arg),
		void *arg) {
	pthread_rwlock_rdlock(&ht_rwlock);
	if (ht_head[type]) {
		struct vuht_entry_t *scanht = ht_head[type];
		do {
			scanht = scanht->next;
			if (scanht->invalid == 0) {
				if ((matching_epoch(scanht->timestamp)) > 0)
					fun(scanht, arg);
			}
		} while (ht_head[type] != NULL && scanht != ht_head[type]);
	}
	pthread_rwlock_unlock(&ht_rwlock);
}

/* mount table creation */
static void vuht_mtab_add(struct vuht_entry_t *ht, void *arg)
{
	FILE *f = arg;

	if (ht->mtabline)
		fprintf(f, "%s\n", ht->mtabline);
}


void vuht_get_mtab(FILE *f) {
	if (f)
		forall_vuht_do(CHECKPATH, vuht_mtab_add, f);
}


void *ht_get_private_data(struct vuht_entry_t *hte) {
	if (hte)
		return hte->private_data;
	else
		return NULL;
}

void ht_set_private_data(struct vuht_entry_t *hte, void *private_data) {
	if (hte)
		hte->private_data = private_data;
}

struct vuht_entry_t *ht_search(uint8_t type, void *arg, int objlen,
		struct vu_service_t *service) {
	struct vuht_entry_t *hte = ht_check(type, arg, NULL, 0);

	if (hte && ((objlen > 0 && objlen != hte->objlen) ||
				(service != NULL && service != hte->service)))
		return NULL;
	return hte;
}

void ht_renew(struct vuht_entry_t *hte) {
	if (hte)
		hte->timestamp = get_vepoch();
}

#if 0
char *ht_get_servicename(struct vuht_entry_t *hte) {
	if (hte && hte->service)
		return hte->service->name;
	else
		return NULL;
}
#endif

struct vu_service_t *ht_get_service(struct vuht_entry_t *hte) {
	if (hte)
		return hte->service;
	else
		return NULL;
}

unsigned long ht_get_mountflags(struct vuht_entry_t *hte) {
	if (hte)
		return hte->mountflags;
	else
		return 0;
}

epoch_t ht_get_vepoch(struct vuht_entry_t *hte) {
	return hte->timestamp;
}

void ht_count_plus1(struct vuht_entry_t *hte) {
#if 0 //XXXX
	if (hte->service_hte == NULL) {
		if (hte->service)
			hte->service_hte =
				vuht_search(CHECKMODULE, hte->service->name, 0, 1);
	}
#endif
	if (hte->service_hte)
		hte->service_hte->count++;
	hte->count++;
}

void ht_count_minus1(struct vuht_entry_t *hte) {
	if (hte->service_hte)
		hte->service_hte->count--;
	hte->count--;
}

int ht_get_count(struct vuht_entry_t *hte) {
	return hte->count;
}

void ht_terminate() {
	forall_ht_terminate(CHECKPATH);
}
