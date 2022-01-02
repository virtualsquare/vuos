/*
 * vudevfuse: /dev/fuse - virtual fuse kernel support
 * Copyright 2022 Renzo Davoli
 *     Virtualsquare & University of Bologna
 *
 * fusenode.c: cache of nodeid + stat data
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <linux/fuse.h>
#include <fusenode.h>
#include <listx.h>

#define FUSENODE_HT_SIZE 64
#define FUSENODE_HT_MASK (FUSENODE_HT_SIZE - 1)

struct fusenode {
	struct list_head pathlink;
	struct list_head nodelink;
	struct list_head lrulink;
	uint64_t hash;
	uint64_t nodeid;
	uint64_t generation;
	struct timespec entry_expire;
	struct timespec attr_expire;
	struct fuse_attr attr;
	uint32_t nlookup;
	char path[];
};

struct fusenode_buf {
	pthread_mutex_t mutex;
	int count;
	int maxlru;
	struct list_head path_ht[FUSENODE_HT_SIZE];
	struct list_head node_ht[FUSENODE_HT_SIZE];
	struct list_head lru;
};

static const struct fuse_attr null_attr;

static inline uint64_t fusenode_hashsum(const char *path) {
	/* djb2 */
	uint64_t sum = 5381;
	for (; *path ; path++)
		sum = ((sum << 5) + sum) + *path; /* hash * 33 + c */
	return sum;
}

static void expiretime (struct timespec *expire, struct timespec *now,
		uint64_t valid, uint32_t valid_nsec) {
	expire->tv_sec = now->tv_sec + valid;
	expire->tv_nsec = now->tv_nsec + valid_nsec;
	while (expire->tv_nsec > 1000000000L) {
		expire->tv_nsec -= 1000000000L;
		expire->tv_sec++;
	}
}

static int timespec_cmp(struct timespec *a, struct timespec *b) {
	if (a->tv_sec > b->tv_sec) return 1;
	if (a->tv_sec < b->tv_sec) return -1;
	if (a->tv_nsec > b->tv_nsec) return 1;
	if (a->tv_nsec < b->tv_nsec) return -1;
	return 0;
}

uint64_t fn_get(struct fusenode_buf *ht,
		const char *path, struct fuse_attr *attr) {
	uint64_t hash = fusenode_hashsum(path);
	uint64_t nodeid = 0;
	struct fusenode *scan;
	pthread_mutex_lock(&ht->mutex);
	list_for_each_entry(scan, &ht->path_ht[hash & FUSENODE_HT_MASK], pathlink) {
		//printf("GET |%s| |%s| %lld %lld\n", path, scan->path, hash, scan->hash);
		if (hash == scan->hash &&
				strcmp(path, scan->path) == 0) {
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			//printf("timecmp +++ %d \n", timespec_cmp(&now, &scan->entry_expire));
			if (timespec_cmp(&now, &scan->entry_expire) > 0)
				break;
			if (attr) {
				if (timespec_cmp(&now, &scan->attr_expire) > 0)
					*attr = null_attr;
				else
					*attr = scan->attr;
				//printf("timecmp >>> %d \n", timespec_cmp(&now, &scan->attr_expire));
			}
			list_del(&scan->lrulink);
			list_add(&scan->lrulink, &ht->lru);
			nodeid = scan->nodeid;
			break;
		}
	}
	pthread_mutex_unlock(&ht->mutex);
	//printf("fn_get %s %d %d\n", path, nodeid, hash & FUSENODE_HT_MASK);
	return nodeid;
}

void fn_add(struct fusenode_buf *ht,
		const char *path, struct fuse_entry_out *entry) {
	struct fusenode *scan;
	struct fusenode *this = NULL;
	uint64_t hash = fusenode_hashsum(path);
	//printf("ADD |%s| %d\n", path, hash & FUSENODE_HT_MASK);
	pthread_mutex_lock(&ht->mutex);
	list_for_each_entry(scan, &ht->path_ht[hash & FUSENODE_HT_MASK], pathlink) {
		if (hash == scan->hash &&
				strcmp(path, scan->path) == 0 &&
				scan->nodeid == entry->nodeid &&
				scan->generation == entry->generation) { // may nodeid change?
			list_del(&scan->lrulink);
			this = scan;
			break;
		}
	}
	if (this == NULL) {
		this = calloc(1, sizeof(struct fusenode) + strlen(path) + 1);
		if (this != NULL) {
			this->nlookup = 0;
			this->hash = hash;
			this->nodeid = entry->nodeid;
			this->generation = entry->generation;
			strcpy(this->path, path);
			list_add(&this->pathlink, &ht->path_ht[hash & FUSENODE_HT_MASK]);
			list_add(&this->nodelink, &ht->node_ht[entry->nodeid & FUSENODE_HT_MASK]);
			ht->count++;
		}
	}
	if (this != NULL) {
		struct timespec now;
		this->nlookup++;
		this->attr = entry->attr;
		clock_gettime(CLOCK_REALTIME, &now);
		expiretime(&this->entry_expire, &now, entry->entry_valid, entry->entry_valid_nsec);
		expiretime(&this->attr_expire, &now, entry->attr_valid, entry->attr_valid_nsec);
		list_add(&this->lrulink, &ht->lru);
	}
	pthread_mutex_unlock(&ht->mutex);
}

uint64_t fn_getnode(struct fusenode_buf *ht,
		uint64_t nodeid,  struct fuse_attr *attr) {
	uint64_t rnodeid = 0;
	struct fusenode *scan;
	pthread_mutex_lock(&ht->mutex);
	list_for_each_entry(scan, &ht->node_ht[nodeid & FUSENODE_HT_MASK], nodelink) {
		if (nodeid == scan->nodeid) {
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			if (timespec_cmp(&now, &scan->entry_expire) > 0)
				break;
			if (timespec_cmp(&now, &scan->attr_expire) > 0)
				*attr = null_attr;
			else
				*attr = scan->attr;
			list_del(&scan->lrulink);
			list_add(&scan->lrulink, &ht->lru);
			rnodeid = nodeid;
			break;
		}
	}
	pthread_mutex_unlock(&ht->mutex);
	return rnodeid;
}

void fn_updatenode(struct fusenode_buf *ht,
		uint64_t nodeid,  struct fuse_attr_out *entry) {
	struct fusenode *scan;
	pthread_mutex_lock(&ht->mutex);
	list_for_each_entry(scan, &ht->node_ht[nodeid & FUSENODE_HT_MASK], nodelink) {
		if (nodeid == scan->nodeid) {
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			expiretime(&scan->attr_expire, &now, entry->attr_valid, entry->attr_valid_nsec);
			scan->attr = entry->attr;
			break;
		}
	}
	pthread_mutex_unlock(&ht->mutex);
}

static void _fn_delnode(struct fusenode *old) {
	list_del(&old->pathlink);
	list_del(&old->nodelink);
	list_del(&old->lrulink);
	free(old);
}

uint64_t fn_delnode(struct fusenode_buf *ht,
		uint64_t nodeid, uint64_t *nlookup) {
	uint64_t rnodeid = 0;
	struct fusenode *scan;
	pthread_mutex_lock(&ht->mutex);
	list_for_each_entry(scan, &ht->node_ht[nodeid & FUSENODE_HT_MASK], nodelink) {
		if (nodeid == scan->nodeid) {
			rnodeid = nodeid;
			*nlookup = scan->nlookup;
			ht->count--;
			_fn_delnode(scan);
			break;
		}
	}
	pthread_mutex_unlock(&ht->mutex);
	return rnodeid;
}

uint64_t fn_forgetlru(struct fusenode_buf *ht, uint64_t *nlookup) {
	uint64_t nodeid = 0;
	pthread_mutex_lock(&ht->mutex);
	if (ht->count > ht->maxlru) {
		struct fusenode *last = list_last_entry(&ht->lru, struct fusenode, lrulink);
		nodeid = last->nodeid;
		*nlookup = last->nlookup;
		ht->count--;
		_fn_delnode(last);
	}
	pthread_mutex_unlock(&ht->mutex);
	return nodeid;
}

struct fusenode_buf *fn_init(int maxlru) {
	struct fusenode_buf *new = calloc(1, sizeof(struct fusenode_buf));
	if (new) {
		pthread_mutex_init(&(new->mutex), NULL);
		struct fuse_entry_out root = {
			.nodeid = FUSE_ROOT_ID,
			.entry_valid = INT64_MAX >> 1 // far away in the future w/o overflow
		};
		new->maxlru = maxlru;
		for (int i = 0; i < FUSENODE_HT_SIZE; i++) {
			INIT_LIST_HEAD(&new->path_ht[i]);
			INIT_LIST_HEAD(&new->node_ht[i]);
		}
		INIT_LIST_HEAD(&new->lru);
		fn_add(new, "", &root);
	}
	return new;
}

void fn_fini(struct fusenode_buf *ht) {
	while(!list_empty(&ht->lru))
		_fn_delnode(list_first_entry(&ht->lru, struct fusenode, lrulink));
	pthread_mutex_destroy(&(ht->mutex));
	free(ht);
}
