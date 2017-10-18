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
	size_t length;
	struct vu_fnode_t *fnode;
	off_t offset;
	struct vu_mmap_area_t *next;
};

struct vu_mmap_t {
	pthread_rwlock_t lock;
	size_t count;
	struct vu_mmap_area_t *area_list_head;
};

static __thread struct vu_mmap_t *vu_mmap = NULL;

void vu_mmap_mmap(uintptr_t addr, size_t length, struct vu_fnode_t *fnode, off_t offset) {
	struct vu_mmap_area_t *new = malloc(sizeof(*new));
	struct vu_mmap_area_t **scan;
	fatal(new);
	new->addr = addr;
	new->length = length;
	new->fnode = fnode;
	new->offset = offset;
	fatal(vu_mmap);
	for (scan = &vu_mmap->area_list_head; *scan != NULL && (*scan)->addr < addr;
			scan = &((*scan)->next))
		;
	vu_fnode_dup(fnode);
	new->next = *scan;
	*scan = new;
}

void vu_mmap_munmap(uintptr_t addr, size_t length) {
	struct vu_mmap_area_t **scan;
	struct vu_mmap_area_t **next;
	/* it seems that the deallocation of ptrheads' stacks happens after
		 vu_mmap_terminate */
	if (vu_mmap == NULL)
		return;
	//fatal(vu_mmap);
	for (scan = &vu_mmap->area_list_head; *scan != NULL; scan = next) {
		struct vu_mmap_area_t *this = *scan;
		next = &((*scan)->next);
		if (addr + length <= this->addr)
			continue;
		if (this->addr + this->length <= addr)
			break;
		if (addr <= this->addr) {
			if (addr + length >= this->addr + this->length) {
				/* entirely in the interval */
				/* unload this->addr,this->length */
				*scan = this->next;
				vu_fnode_close(this->fnode);
				free(this);
				next = scan;
			} else {
				/* partial unmapping (heading) */
				/* unload this->addr, addr + length - this->addr */
				this->length = this->addr + this->length - (addr + length);
				this->offset += addr + length - this->addr;
				this->addr = addr;
				break;
			}
		} else {
			if (addr + length >= this->addr + this->length) {
				/* partial unmapping (trailing)*/
				/* unload  addr, this->addr + this->length - addr */
				this->length = addr + length - this->addr;
			} else {
				/* partial **nested** interval */
				/* unload addr, length */
				struct vu_mmap_area_t *new = malloc(sizeof(*new));
				fatal(new);
				new->addr = this->addr;
				new->length = addr - this->addr;
				new->fnode = this->fnode;
				new->offset = this->offset;
				new->next = this;
				*scan = new;
				this->length = this->addr + this->length - (addr + length);
				this->offset += addr + length - this->addr;
				this->addr = addr + length;
				vu_fnode_dup(this->fnode);
				break;
			}
		}
	}
}

void vu_mmap_mremap(uintptr_t addr, size_t length, uintptr_t newaddr, size_t newlength) {
	struct vu_mmap_area_t **scan;
	struct vu_mmap_area_t *this;
  fatal(vu_mmap);
	for (scan = &vu_mmap->area_list_head; *scan != NULL && (*scan)->addr < addr;
			scan = &((*scan)->next))
    ;
	this = *scan;
	if (this->addr == addr && this->length == length) {
		this->addr = newaddr;
		this->length = newlength;
		for (scan = &vu_mmap->area_list_head; *scan != NULL && (*scan)->addr < newaddr;
				scan = &((*scan)->next))
			;
		this->next = *scan;
		*scan = this;
	}
}

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
		/* sync and close all the mmapped areas */
		vu_mmap_munmap(0, (size_t) -1);
		vu_mmap = NULL;
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

