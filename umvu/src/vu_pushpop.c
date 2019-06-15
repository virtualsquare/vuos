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

#include <umvu_peekpoke.h>
#include <vu_pushpop.h>

/* push and pop data on the user process stack */
#define __WORDMASK ((__WORDSIZE / 8) - 1)
#define WORDALIGN(X) (((X) + __WORDMASK) & ~__WORDMASK)

syscall_arg_t vu_push(struct syscall_descriptor_t *sd, void *buf, size_t datalen) {
	sd->stack_pointer -= WORDALIGN(datalen);
	umvu_poke_data(sd->stack_pointer, buf, datalen);
	return sd->stack_pointer;
}

void vu_pop(struct syscall_descriptor_t *sd, void *buf, size_t datalen) {
	umvu_peek_data(sd->stack_pointer, buf, datalen);
	sd->stack_pointer += WORDALIGN(datalen);
}
