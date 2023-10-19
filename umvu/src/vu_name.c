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
#include <string.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <vu_name.h>

static pthread_mutex_t vu_name_mutex = PTHREAD_MUTEX_INITIALIZER;
static char vu_name[_UTSNAME_LENGTH];

void set_vu_name(char *name) {
	pthread_mutex_lock(&vu_name_mutex);
	vu_name[_UTSNAME_LENGTH - 1 ] = 0;
	strncpy(vu_name, name, _UTSNAME_LENGTH - 1);
	pthread_mutex_unlock(&vu_name_mutex);
}

void get_vu_name(char *name, size_t len) {
	if (len > _UTSNAME_LENGTH)
		len = _UTSNAME_LENGTH;
	pthread_mutex_lock(&vu_name_mutex);
	memcpy(name, vu_name, len);
	pthread_mutex_unlock(&vu_name_mutex);
}
