/*
 * vudevfuse: /dev/fuse - virtual fuse kernel support
 * Copyright 2022 Renzo Davoli
 *     Virtualsquare & University of Bologna
 *
 * fusereqq.c: manage request queues:
 *           store pending requests to the user level daemon
 *           and match replies
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

#include <fusereqq.h>

void fusereq_enqueue(struct fusereq *req, struct fusereq **tail) {
	struct fusereq *last = *tail;
	if (last == NULL)
		req->next = req;
	else {
		req->next = last->next;
		last->next = req;
	}
	*tail = req;
}

struct fusereq *fusereq_dequeue(struct fusereq **tail) {
	struct fusereq *last = *tail;
	if (last == NULL)
		return NULL;
	struct fusereq *first = last->next;
	if (last == first)
		*tail = NULL;
	else
		last->next = first->next;
	first->next = NULL;
	return first;
}

struct fusereq *fusereq_outqueue(uint64_t unique, struct fusereq **tail) {
	struct fusereq *prev, *this;
	for (prev = *tail, this = prev->next;
			this != *tail;
			prev = this, this = prev->next)
		if (this->reqh.unique == unique)
			break;
	if (this->reqh.unique == unique) {
		if (this == *tail)
			*tail = (prev == *tail) ? NULL : prev;
		prev->next = this->next;
		return this;
	} else
		return NULL;
}
