#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <xcommon.h>
#include <vu_file_table.h>
#include <vu_log.h>
#include <umvu_tracer.h>

struct vu_mmap_area_t {
	uintptr_t addr;
	uintptr_t length;
	struct vu_fnode_t *fnode;
	struct vu_mmap_area_t *next;
};

struct vu_mmap_t {
	pthread_rwlock_t lock;
	size_t count;
	struct vu_mmap_area_t *area_list_head;
};

static __thread struct vu_mmap_t *vu_mmap = NULL;

static void vu_mmap_create(void) {
	struct vu_mmap_t *newmmap;

	newmmap = malloc(sizeof(struct vu_mmap_t));
	fatal(newmmap);
	newmmap->count = 1;
	newmmap->area_list_head = NULL;
	pthread_rwlock_init(&newmmap->lock, NULL);
	vu_mmap = newmmap;
}

static void *vu_mmap_clone(void *arg) {
	int flags = *(int *)arg;
	struct vu_mmap_t *newmmap;

	if (flags & CLONE_VM) {
		pthread_rwlock_wrlock(&vu_mmap->lock);
		newmmap = vu_mmap;
		newmmap->count++;
		pthread_rwlock_unlock(&vu_mmap->lock);
		return newmmap;
	} else {
		newmmap = malloc(sizeof(struct vu_mmap_t));
		fatal(newmmap);
		newmmap->count = 1;
		newmmap->area_list_head = NULL;
		pthread_rwlock_init(&newmmap->lock, NULL);
	}
	return newmmap;
}

static void vu_mmap_terminate(void) {
	pthread_rwlock_wrlock(&vu_mmap->lock);
	vu_mmap->count -= 1;
	if (vu_mmap->count == 0) {
		struct vu_mmap_t *old_vu_mmap = vu_mmap;
		vu_mmap = NULL;
		/* sync and close all the mmapped areas */
		pthread_rwlock_unlock(&old_vu_mmap->lock);
		pthread_rwlock_destroy(&old_vu_mmap->lock);
		xfree(old_vu_mmap);
	} else
		pthread_rwlock_unlock(&vu_mmap->lock);
}

static void vu_mmap_exec(void) {
	vu_mmap_terminate();
	vu_mmap_create();
}

static void *vu_mmap_tracer_upcall(inheritance_state_t state, void *arg) {
	void *ret_value = NULL;
	switch (state) {
		case INH_CLONE:
			ret_value = vu_mmap_clone(arg);
			break;
		case INH_START:
			vu_mmap = arg;
			break;
		case INH_EXEC:
			vu_mmap_exec();
			break;
		case INH_TERMINATE:
			vu_mmap_terminate();
			break;
	}
	return ret_value;
}

__attribute__((constructor))
	static void init(void) {
		vu_mmap_create();
		umvu_inheritance_upcall_register(vu_mmap_tracer_upcall);
	}

