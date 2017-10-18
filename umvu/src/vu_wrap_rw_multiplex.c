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
#include <sys/stat.h>
#include <errno.h>
#include <xstat.h>
#include <syscall_table.h>
#include <vu_execute.h>

wrapf_t wi_NULL, wd_NULL, wo_NULL;
static wrapf_t wi_einval;
static wrapf_t *x_wi_read[S_TYPES] = {S_TYPES_INIT(wi_einval)};
static wrapf_t *x_wd_read[S_TYPES] = {S_TYPES_INIT(wd_NULL)};
static wrapf_t *x_wo_read[S_TYPES] = {S_TYPES_INIT(wo_NULL)};
static wrapf_t *x_wi_write[S_TYPES] = {S_TYPES_INIT(wi_einval)};
static wrapf_t *x_wd_write[S_TYPES] = {S_TYPES_INIT(wd_NULL)};
static wrapf_t *x_wo_write[S_TYPES] = {S_TYPES_INIT(wo_NULL)};

static void wi_einval(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht != NULL) {
		sd->ret_value = -EINVAL;
		sd->action = SKIPIT;
	}
}

void set_wi_read(mode_t mode, wrapf_t *handler) {
	x_wi_read[S_MODE2TYPE(mode)] = handler;
}

void set_wd_read(mode_t mode, wrapf_t *handler) {
	x_wd_read[S_MODE2TYPE(mode)] = handler;
}

void set_wo_read(mode_t mode, wrapf_t *handler) {
	x_wo_read[S_MODE2TYPE(mode)] = handler;
}

void set_wi_write(mode_t mode, wrapf_t *handler) {
	x_wi_write[S_MODE2TYPE(mode)] = handler;
}

void set_wd_write(mode_t mode, wrapf_t *handler) {
	x_wd_write[S_MODE2TYPE(mode)] = handler;
}

void set_wo_write(mode_t mode, wrapf_t *handler) {
	x_wo_write[S_MODE2TYPE(mode)] = handler;
}

void wi_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wi_read[S_MODE2TYPE(mode)](ht, sd);
}

void wi_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wi_write[S_MODE2TYPE(mode)](ht, sd);
}

void wd_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wd_read[S_MODE2TYPE(mode)](ht, sd);
}

void wd_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wd_write[S_MODE2TYPE(mode)](ht, sd);
}

void wo_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wo_read[S_MODE2TYPE(mode)](ht, sd);
}

void wo_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wo_write[S_MODE2TYPE(mode)](ht, sd);
}

