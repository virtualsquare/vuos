/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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
#include<stdio.h>
#include<stdlib.h>
#include<vu_log.h>
#include<vu_inheritance.h>

struct inheritance_elem_t {
	inheritance_upcall_t upcall;
	struct inheritance_elem_t *next;
};

static struct inheritance_elem_t *inheritance_upcall_list_h = NULL;
static struct inheritance_elem_t *inheritance_upcall_list_t = NULL;
static int inheritance_upcall_list_count;

void vu_inheritance_upcall_register(inheritance_upcall_t upcall) {
	struct inheritance_elem_t *new;
	new = malloc(sizeof(struct inheritance_elem_t));
	fatal(new);
	new->upcall = upcall;
	new->next = NULL;
	if (inheritance_upcall_list_t == NULL)
		inheritance_upcall_list_h = new;
	else
		inheritance_upcall_list_t->next = new;
	inheritance_upcall_list_t = new;
	inheritance_upcall_list_count++;
}

void vu_inheritance_call(inheritance_state_t state, void **inout, void *arg) {
	struct inheritance_elem_t *scan;
	for (scan = inheritance_upcall_list_h; scan != NULL; scan = scan->next) {
		char *upcallarg = (arg != NULL) ? arg :
			((inout != NULL) ? *inout : NULL);
		void *result = scan->upcall(state, upcallarg);
		if (inout != NULL)
			*(inout++) = result;
	}
}

size_t vu_inheritance_inout_size(void) {
	return inheritance_upcall_list_count * sizeof(void *);
}
