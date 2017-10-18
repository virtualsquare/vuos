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
#include <unistd.h>
#include <r_table.h>
#include <vu_log.h>
#include <vu_initfini.h>
#include <vu_tmpdir.h>

#define TMP_PATTERN "/tmp/.vu_%010lu_XXXXXX"
#define TMP_PATTERN_EXAMPLE "/tmp/.vu_0123456789_XXXXXX"
static char dirpath[sizeof(TMP_PATTERN_EXAMPLE)+1];

char *vu_tmpdirpath(void) {
	return dirpath;
}

static void dirpath_init(void) {
	snprintf(dirpath, sizeof(TMP_PATTERN_EXAMPLE)+1, TMP_PATTERN, (unsigned long) getpid());
	fatal(mkdtemp(dirpath));
	r_chdir(dirpath);
}

static void dirpath_fini(void) {
	r_rmdir(dirpath);
}

__attribute__((constructor))
	static void init (void) {
		vu_constructor_register(dirpath_init);
		vu_destructor_register(dirpath_fini);
	}
