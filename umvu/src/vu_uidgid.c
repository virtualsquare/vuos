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
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <xcommon.h>
#include <vu_log.h>
#include <vu_inheritance.h>
#include <vu_uidgid.h>

/* In Linux all uid/gid are defined per thread level */
/* file system entry */
struct vu_uidgid_t {
	uid_t ruid, euid, suid, fsuid;
	gid_t rgid, egid, sgid, fsgid;
	int supgid_size;
	gid_t supgid[];
};

static __thread struct vu_uidgid_t *vu_uidgid = NULL;

void vu_uidgid_getresfuid(uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid) {
	if (ruid != NULL)
		*ruid = vu_uidgid->ruid;
	if (euid != NULL)
		*euid = vu_uidgid->euid;
	if (suid != NULL)
		*suid = vu_uidgid->suid;
	if (fsuid != NULL)
		*fsuid = vu_uidgid->fsuid;
}

void vu_uidgid_setresfuid(const uid_t ruid, const uid_t euid, const uid_t suid, const uid_t fsuid) {
	if (ruid != (uid_t) -1)
		vu_uidgid->ruid = ruid;
	if (euid != (uid_t) -1)
		vu_uidgid->euid = euid;
	if (suid != (uid_t) -1)
		vu_uidgid->suid = suid;
	if (fsuid != (uid_t) -1)
		vu_uidgid->fsuid = fsuid;
}

void vu_uidgid_getresfgid(gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid) {
	if (rgid != NULL)
		*rgid = vu_uidgid->rgid;
	if (egid != NULL)
		*egid = vu_uidgid->egid;
	if (sgid != NULL)
		*sgid = vu_uidgid->sgid;
	if (fsgid != NULL)
		*fsgid = vu_uidgid->fsgid;
}

void vu_uidgid_setresfgid(const gid_t rgid, const gid_t egid, const gid_t sgid, const gid_t fsgid) {
	if (rgid != (gid_t) -1)
		vu_uidgid->rgid = rgid;
	if (egid != (gid_t) -1)
		vu_uidgid->egid = egid;
	if (sgid != (gid_t) -1)
		vu_uidgid->sgid = sgid;
	if (fsgid != (gid_t) -1)
		vu_uidgid->fsgid = fsgid;
}

int vu_uidgid_getgroups(int size, gid_t list[]) {
	int supgid_size = vu_uidgid->supgid_size;
	if (size == 0)
		return supgid_size;
	else if (size < supgid_size)
		return errno = EINVAL, -1;
	else if (list == NULL)
		return errno = EFAULT, -1;
	else {
		memcpy(list, vu_uidgid->supgid, supgid_size * sizeof(gid_t));
		return supgid_size;
	}
}

int vu_uidgid_setgroups(int size, gid_t list[]) {
	struct vu_uidgid_t *newuidgid;
	newuidgid = realloc(vu_uidgid, sizeof(struct vu_uidgid_t) + size * sizeof(gid_t));
	if (newuidgid == NULL)
		return -1;
	else {
		vu_uidgid = newuidgid;
		vu_uidgid->supgid_size = size;
		memcpy(vu_uidgid->supgid, list, size * sizeof(gid_t));
		return 0;
	}
}

static void vu_uidgid_create(void) {
	int supgid_size = getgroups(0, NULL);
	struct vu_uidgid_t *newuidgid;

	if (supgid_size < 0)
		supgid_size = 0;
	newuidgid = malloc(sizeof(struct vu_uidgid_t) + supgid_size * sizeof(gid_t));
	fatal(newuidgid);
	getresuid(&newuidgid->ruid, &newuidgid->euid, &newuidgid->suid);
	getresgid(&newuidgid->rgid, &newuidgid->egid, &newuidgid->sgid);
	newuidgid->fsuid = setfsuid(-1);
	newuidgid->fsgid = setfsgid(-1);
	newuidgid->supgid_size = supgid_size;
	getgroups(supgid_size, newuidgid->supgid);
	vu_uidgid = newuidgid;
}

static void *vu_uidgid_clone(int flags) {
	struct vu_uidgid_t *newuidgid;
	int supgid_size = vu_uidgid->supgid_size;

	newuidgid = malloc(sizeof(struct vu_uidgid_t) + supgid_size * sizeof(gid_t));
	fatal(newuidgid);
	*newuidgid = *vu_uidgid;
	memcpy(newuidgid->supgid, vu_uidgid->supgid, supgid_size * sizeof(gid_t));
	return newuidgid;
}

static void vu_uidgid_terminate(void) {
	xfree(vu_uidgid);
}

static void *vu_uidgid_tracer_upcall(inheritance_state_t state, void *arg) {
	void *ret_value = NULL;
	switch (state) {
		case INH_CLONE:
			ret_value = vu_uidgid_clone(*(int *)arg);
			break;
		case INH_PTHREAD_CLONE:
			ret_value = vu_uidgid_clone(0);
			break;
		case INH_START:
		case INH_PTHREAD_START:
			vu_uidgid = arg;
			break;
		case INH_TERMINATE:
		case INH_PTHREAD_TERMINATE:
			vu_uidgid_terminate();
			break;
		default:
			break;
	}
	return ret_value;
}

__attribute__((constructor))
	static void init(void) {
		vu_uidgid_create();
		vu_inheritance_upcall_register(vu_uidgid_tracer_upcall);
	}
