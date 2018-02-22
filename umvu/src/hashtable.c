/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   UMDEV: Virtual Device in Userspace
 *
 */

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

/**Hashtable object definition.
   vuht_entry_t:
	 @obj: hash key
	 @mtabline: mount tab line
	 @type: type
	 @trailingnumbers: boolean, match pathnames with trailing numbers
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
	struct vu_service_t *service;
	struct vuht_entry_t *service_hte;
	void *private_data;
	int objlen;
	long hashsum;
	_Atomic int count;
	/* confirmfun_t */
	confirmfun_t confirmfun;
	struct vuht_entry_t *prev, *next, **pprevhash, *nexthash;
};

#define VUHT_DELETED(ht) ((ht)->next == NULL)

/* it must be a power of two (masks are used instead of modulo). */
#define VU_HASHTABLE_SIZE 512
#define VU_HASHTABLE_MASK (VU_HASHTABLE_SIZE-1)

/* ReadWrite lock to access the Hashtable. */
static pthread_rwlock_t vuht_rwlock = PTHREAD_RWLOCK_INITIALIZER;
/* this is THE hash */
static struct vuht_entry_t *vuht_hash[VU_HASHTABLE_SIZE];

/* null tags have separate a separate list.*/
static struct vuht_entry_t *vuht_hash0[NCHECKS];

/* heads of the list of hash entries of the same type.*/
static struct vuht_entry_t *vuht_head[NCHECKS];

static inline struct vuht_entry_t *vuht_alloc() {
	struct vuht_entry_t *rv = malloc(sizeof (struct vuht_entry_t));
	fatal(rv);
	return rv;
}

/* free of vuht_entry_t */
static void vuht_free(struct vuht_entry_t *ht) {
	free(ht->obj);
	if (ht->mtabline)
		free(ht->mtabline);
	free(ht);
}

/* hash function */
/** hash sum and mod are separate functions:
	 hash sums are used to quickly eliminate false positives,
	 intermediate results can be completed during the scan. */
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
/** View-OS permits "mount" of things like /dev/hda[0-9]* .*/
static inline int trailnum(char *s)
{
	/** "at least one" the first element needs a special case.
     performance:  >'9' is the most frequent case, <'0' are quite rare
     in pathnames, the end of string is more common. */
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

/** During the vuht_internal_search: access the hash table only if this function returns 1.
	The scan is perfomed step by step, checking the objc (for pathnames) or
	len (for integers or sequence of integers).*/
static int vuht_scan_stop(uint8_t type, char *objc, int len, int exact)
{
	switch (type) {
		case CHECKPATH:
			return (
					*objc == 0 /* this is the end of a string */
					||
					(!exact           /* or when subtring match are allowed */
					 && (*objc == '/' 
						 /* or if there are trailing numbers e.g. /dev/hda1, hda2 etc */
						 || trailnum(objc))));
		case CHECKBINFMT:
			return (*objc == 0 /* this is the end of a string */
					||
					(!exact /* or when subtring match are allowed */
					 &&
					 *objc == '/')); 
		case CHECKSOCKET:
		case CHECKCHRDEVICE:
		case CHECKBLKDEVICE:
		case CHECKSC: /* array of int, or null keys */
			return ((len % sizeof(int)) == 0);
		case CHECKIOCTL: 
			return ((len % sizeof(unsigned long)) == 0);
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

/** Terminate the scan: the vuht_internal_search has scanned the obj or has reached is objlen.*/
static inline int vuht_scan_terminate(uint8_t type, char *objc, int len,
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
		case CHECKIOCTL:
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

/**A list of possible ht elements (carrot) is generated,then the right element is  choosen in this list
	by its confirmation function.*/
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

	pthread_rwlock_rdlock(&vuht_rwlock);
	while (1) {
		if (vuht_scan_stop(type, objc, len, exact)) {
			hash = hashmod(sum);
			ht = vuht_hash[hash];			//will it be overwrited??
			/**Modules can register NULL obj with len == 0.
				These obj of the same type have the same hash sum and key so their collision list is
				stored in vuht_hash0[].*/								
			ht=(len) ? vuht_hash[hash] : vuht_hash0[type];					
			while (ht != NULL) {
				if (type == ht->type && sum == ht->hashsum &&
						memcmp(obj, ht->obj, len) == 0 &&
						(ht->trailingnumbers || !trailnum(objc)) &&
						(tst > ht->timestamp) &&
						(e = matching_epoch(ht->timestamp)) > 0) {
					/*carrot add*/
					if (ht->confirmfun == NEGATIVE_MOUNT)  				//a comment is required
						carh = carrot_delete(carh, ht->private_data);
					else
						carh = carrot_insert(carh, ht, e, has_exception);
				}
				ht = ht->nexthash;
			}
			if (vuht_scan_terminate(type, objc, len, objlen))
				break;
		}
		/**The search is done incrementally, iterating on obj and incrementing len until the correct hash table collision list is founded.*/
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
	pthread_rwlock_unlock(&vuht_rwlock);
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
		confirmfun_t confirmfun, void *private_data,
		int permanent)
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
	new->private_data = private_data;
	new->service = service;
	new->service_hte = service->service_ht;
	new->confirmfun = confirmfun;
	new->count = (permanent != 0);
	if (service->service_ht)
		vuht_pick_again(service->service_ht);

	new->hashsum = hashsum(type, new->obj, new->objlen);
	pthread_rwlock_wrlock(&vuht_rwlock);
	/* add it to the list of hash entry of this type */
	if (vuht_head[type]) {
		new->next=vuht_head[type]->next;
		new->prev=vuht_head[type];
		new->next->prev=new;
		new->prev->next=new;
		vuht_head[type]=new;
	} else
		vuht_head[type]=new->next=new->prev=new;
	/* add it to the right hash collision list */
	if (objlen==0)
		hashhead=&vuht_hash0[type];
	else
		hashhead=&vuht_hash[hashmod(new->hashsum)];
	if (*hashhead)
		(*hashhead)->pprevhash=&(new->nexthash);
	new->nexthash=*hashhead;
	new->pprevhash=hashhead;
	*hashhead=new;
	pthread_rwlock_unlock(&vuht_rwlock);

	return new;
}

struct vuht_entry_t *vuht_add(uint8_t type, void *obj, int objlen,
		struct vu_service_t *service, confirmfun_t confirmfun,
		void *private_data, int permanent) {
	return internal_vuht_add(type, obj, objlen, 0, NULL, service, 1,
			confirmfun, private_data, permanent);
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
		/**mount tab line generation.*/
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
			private_data, permanent_mount(mountopts));
	if (rv == NULL && mtabline != NULL)
		free(mtabline);
	return rv;
}

/* unlink an element from the hash table */
static int vuht_del_locked(struct vuht_entry_t *ht, int delayed) {
	uint8_t type = ht->type;
	if (ht->count > delayed)
		return -EBUSY;
	if (VUHT_DELETED(ht))
		return -EINVAL;
	if (ht == vuht_head[type]) {
		if (ht->next == ht)
			vuht_head[type] = NULL;
		else
			vuht_head[type] = ht->prev;
	}
	ht->prev->next = ht->next;
	ht->next->prev = ht->prev;
	*(ht->pprevhash) = ht->nexthash;
	if (ht->nexthash)
		ht->nexthash->pprevhash = ht->pprevhash;
	if (ht->service_hte && ht->service_hte != ht)
		vuht_drop(ht->service_hte);
	ht->service_hte = NULL;
	ht->next = ht->prev = ht->nexthash = NULL;
	ht->pprevhash = NULL;
	if (ht->count == 0)
		vuht_free(ht);
	return 0;
}

int vuht_del(struct vuht_entry_t *ht, int delayed) {
	if (ht) {
		int ret_value;
		pthread_rwlock_wrlock(&vuht_rwlock);
		ret_value = vuht_del_locked(ht, delayed & 1);
		pthread_rwlock_unlock(&vuht_rwlock);
		return ret_value;
	} else
		return -ENOENT;
}

/* searching API */
struct vuht_entry_t *vuht_pick(uint8_t type, void *arg, struct vu_stat *st, int setepoch) {
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
		case CHECKIOCTL:
			hte = vuht_search(type, arg, sizeof(unsigned long), 0);
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
	if (hte) {
		hte->count++;
		if (setepoch)
			set_vepoch(hte->timestamp);
	}
	return hte;
}

void vuht_pick_again(struct vuht_entry_t *hte) {
	if (hte)
		hte->count++;
}

void vuht_drop(struct vuht_entry_t *hte) {
	if (hte)
		hte->count--;
	if (hte->count == 0 && VUHT_DELETED(hte))
		vuht_free(hte);
}

/** reverse scan of hash table elements, useful to close all files.  */
static void forall_vuht_terminate(uint8_t type)
{
	pthread_rwlock_rdlock(&vuht_rwlock);
	if (vuht_head[type]) {
		struct vuht_entry_t *scanht = vuht_head[type];
		struct vuht_entry_t *next = scanht;
		do {
			scanht = next;
		} while (vuht_head[type] != NULL && next != vuht_head[type]);
	}
	pthread_rwlock_unlock(&vuht_rwlock);
}

void forall_vuht_do(uint8_t type,
		void (*fun)(struct vuht_entry_t *ht, void *arg),
		void *arg) {
	pthread_rwlock_rdlock(&vuht_rwlock);
	if (vuht_head[type]) {
		struct vuht_entry_t *scanht = vuht_head[type];
		do {
			scanht = scanht->next;
			if ((matching_epoch(scanht->timestamp)) > 0)
				fun(scanht, arg);
		} while (vuht_head[type] != NULL && scanht != vuht_head[type]);
	}
	pthread_rwlock_unlock(&vuht_rwlock);
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


void *vuht_get_private_data(struct vuht_entry_t *hte) {
	if (hte)
		return hte->private_data;
	else
		return NULL;
}

void vuht_set_private_data(struct vuht_entry_t *hte, void *private_data) {
	if (hte)
		hte->private_data = private_data;
}

#if 0
struct vuht_entry_t *vuht_search(uint8_t type, void *arg, int objlen,
		struct vu_service_t *service) {
	struct vuht_entry_t *hte = vuht_pick(type, arg, NULL, 0);

	if (hte && ((objlen > 0 && objlen != hte->objlen) ||
				(service != NULL && service != hte->service)))
		return NULL;
	return hte;
}
#endif

void vuht_renew(struct vuht_entry_t *hte) {
	if (hte)
		hte->timestamp = get_vepoch();
}

#if 0
char *vuht_get_servicename(struct vuht_entry_t *hte) {
	if (hte && hte->service)
		return hte->service->name;
	else
		return NULL;
}
#endif

struct vu_service_t *vuht_get_service(struct vuht_entry_t *hte) {
	if (hte)
		return hte->service;
	else
		return NULL;
}

unsigned long vuht_get_mountflags(struct vuht_entry_t *hte) {
	if (hte)
		return hte->mountflags;
	else
		return 0;
}

epoch_t vuht_get_vepoch(struct vuht_entry_t *hte) {
	return hte->timestamp;
}

int vuht_get_count(struct vuht_entry_t *hte) {
	return hte->count;
}

void vuht_terminate() {
	forall_vuht_terminate(CHECKPATH);
}
