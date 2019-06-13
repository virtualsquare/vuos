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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <epoch.h>
#include <carrot.h>
#include <errno.h>
#include <pthread.h>
#include <vu_log.h>

/* CARROT_FREE_LIST: recycle previously allocated struct carrot_t elements. */
#define CARROT_FREE_LIST

struct carrot_t {
	struct vuht_entry_t *elem;
	epoch_t time;
	struct carrot_t *next;
};

#ifdef CARROT_FREE_LIST
pthread_mutex_t carrot_free_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct carrot_t *carrot_free_head = NULL;

static struct carrot_t *carrot_alloc() {
	struct carrot_t *retvalue = NULL;
	pthread_mutex_lock(&carrot_free_mutex);
	if (carrot_free_head == NULL) {
		pthread_mutex_unlock(&carrot_free_mutex);
		retvalue = malloc(sizeof(struct carrot_t));
		fatal(retvalue);
	} else {
		retvalue = carrot_free_head;
		carrot_free_head = carrot_free_head->next;
		pthread_mutex_unlock(&carrot_free_mutex);
	}
	return retvalue;
}

void carrot_free(struct carrot_t *old) {
	if (old != NULL) {
		struct carrot_t *scan;
		pthread_mutex_lock(&carrot_free_mutex);
		for (scan = old; scan->next != NULL; scan = scan->next)
			;
		scan->next = carrot_free_head;
		carrot_free_head = old;
		pthread_mutex_unlock(&carrot_free_mutex);
	}
}

#else

static struct carrot_t *carrot_alloc() {
	struct carrot_t *rv = NULL;
	rv = malloc(sizeof(struct carrot_t));
	fatal(rv);
	return rv;
}

void carrot_free(struct carrot_t *old) {
	while (old) {
		struct carrot_t *next;
		next = old->next;
		free(old);
		old = next;
	}
}
#endif

/* insert an element in the carrot.
 *   If the element is "newer":
 *      if there are exception: add an element as first element of the carrot.
 *      otherwise: then new carrot has only one element (eventual existing carrot is deleted */

struct carrot_t *carrot_insert(struct carrot_t *head, struct vuht_entry_t *elem, epoch_t time,
		    int (*has_exception)(struct vuht_entry_t *)) {
	if (head == NULL ||      /* empty carrot */
			time > head->time) { /* this is newer */
		if (head == NULL || has_exception(elem)) {
			struct carrot_t *rv;
			rv = carrot_alloc();
			rv->elem = elem;
			rv->time = time;
			rv->next = head;
			return rv;
		} else {
			head->elem = elem;
			head->time = time;
			carrot_free(head->next);
			head->next = NULL;
			return head;
		}
	} else {
		if (has_exception(head->elem))
			head->next = carrot_insert(head->next, elem, time, has_exception);
		return head;
	}
}

/* delete the carrot */
struct carrot_t *carrot_delete(struct carrot_t *head, struct vuht_entry_t *elem) {
	if (head == NULL)
		return NULL;
	else {
		if (head->elem == elem) {
			struct carrot_t *tail = head->next;
			head->next = NULL;
			carrot_free(head);
			return tail;
		} else {
			head->next = carrot_delete(head->next, elem);
			return head;
		}
	}
}

/* return the first element in carrot
 * which has no exceptions *OR*
 * whose exception function return false */
struct vuht_entry_t *carrot_check(struct carrot_t *head,
		int (*confirm)(struct vuht_entry_t *elem, void *opaque), void *opaque) {
	struct vuht_entry_t *ht = NULL;
	if (head != NULL) {
		struct carrot_t *curcar;
		for (curcar = head; curcar != NULL; curcar = curcar->next) {
			if (confirm(curcar->elem, opaque))
				break;
		}
		if (curcar != NULL)
			ht = curcar->elem;
		carrot_free(head);
	}
	return ht;
}

