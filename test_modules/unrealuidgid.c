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
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <vumodule.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/fsuid.h>

VU_PROTOTYPES(unrealuidgid)

	struct vu_module_t vu_module = {
		.name = "unrealuidgid",
		.description = "virtualize uid gid"
	};

struct vu_uid_gid_t {
  pthread_rwlock_t lock;
  uid_t ruid, euid, suid, fsuid;
  gid_t rgid, egid, sgid, fsgid;
	int ngroups;
	gid_t *groups;
  size_t count;
};

static __thread struct vu_uid_gid_t *vu_uid_gid = NULL;

static void vu_uid_gid_create(void) {
  struct vu_uid_gid_t *new;

  new = malloc(sizeof(struct vu_uid_gid_t));
  getresuid(&new->ruid, &new->euid, &new->suid);
  getresgid(&new->rgid, &new->egid, &new->sgid);
  new->fsuid = setfsuid(-1);
  new->fsgid = setfsgid(-1);
  new->count = 1;
	new->ngroups = getgroups(0, NULL);
	new->groups = malloc(new->ngroups * sizeof(gid_t));
	getgroups(new->ngroups, new->groups);
  pthread_rwlock_init(&new->lock, NULL);
  vu_uid_gid = new;
}

static void vu_uid_gid_modify_lock(void) {
	pthread_rwlock_wrlock(&vu_uid_gid->lock);
	if (vu_uid_gid->count > 1) {
		struct vu_uid_gid_t *new;
		new = malloc(sizeof(struct vu_uid_gid_t));
		new->ruid = vu_uid_gid->ruid;
		new->euid = vu_uid_gid->euid;
		new->suid = vu_uid_gid->suid;
		new->fsuid = vu_uid_gid->fsuid;
		new->rgid = vu_uid_gid->rgid;
		new->egid = vu_uid_gid->egid;
		new->sgid = vu_uid_gid->sgid;
		new->fsgid = vu_uid_gid->fsgid;
		new->ngroups = vu_uid_gid->ngroups;
		if (new->ngroups <= 0)
			new->groups = NULL;
		else {
			new->groups = malloc(new->ngroups * sizeof(gid_t));
			memcpy(new->groups, vu_uid_gid->groups, new->ngroups * sizeof(gid_t));
		}
		pthread_rwlock_init(&new->lock, NULL);
		new->count = 1;
		vu_uid_gid->count -= 1;
		pthread_rwlock_unlock(&vu_uid_gid->lock);
		vu_uid_gid = new;
		pthread_rwlock_wrlock(&vu_uid_gid->lock);
	}
}

int vu_unrealuidgid_setresfuid(uid_t ruid, uid_t euid, uid_t suid, uid_t fsuid, void *private) {
	if (vu_uid_gid == NULL)
		vu_uid_gid_create();
	vu_uid_gid_modify_lock();
	if (ruid != (uid_t) -1) vu_uid_gid->ruid = ruid;
	if (euid != (uid_t) -1) vu_uid_gid->euid = euid;
	if (suid != (uid_t) -1) vu_uid_gid->suid = suid;
	if (fsuid != (uid_t) -1) vu_uid_gid->fsuid = fsuid;
	pthread_rwlock_unlock(&vu_uid_gid->lock);
	return 0;
}

int vu_unrealuidgid_getresfuid(uid_t *ruid, uid_t *euid, uid_t *suid,
		uid_t *fsuid, void *private) {
	if (vu_uid_gid != NULL) {
		pthread_rwlock_rdlock(&vu_uid_gid->lock);
		if (ruid != NULL) *ruid = vu_uid_gid->ruid;
		if (euid != NULL) *euid = vu_uid_gid->euid;
		if (suid != NULL) *suid = vu_uid_gid->suid;
		if (fsuid != NULL) *fsuid = vu_uid_gid->fsuid;
		pthread_rwlock_unlock(&vu_uid_gid->lock);
	} else {
		if (fsuid != NULL)
			*fsuid = setfsuid(-1);
		getresuid(ruid, euid, suid);
	}
	return 0;
}

int vu_unrealuidgid_setresfgid(gid_t rgid, gid_t egid, gid_t sgid, gid_t fsgid, void *private) {
  if (vu_uid_gid == NULL)
    vu_uid_gid_create();
	vu_uid_gid_modify_lock();
  if (rgid != (gid_t) -1) vu_uid_gid->rgid = rgid;
  if (egid != (gid_t) -1) vu_uid_gid->egid = egid;
  if (sgid != (gid_t) -1) vu_uid_gid->sgid = sgid;
  if (fsgid != (gid_t) -1) vu_uid_gid->fsgid = fsgid;
  pthread_rwlock_unlock(&vu_uid_gid->lock);
  return 0;
}

int vu_unrealuidgid_getresfgid(gid_t *rgid, gid_t *egid, gid_t *sgid,
    gid_t *fsgid, void *private) {
  if (vu_uid_gid != NULL) {
    pthread_rwlock_rdlock(&vu_uid_gid->lock);
    if (rgid != NULL) *rgid = vu_uid_gid->rgid;
    if (egid != NULL) *egid = vu_uid_gid->egid;
    if (sgid != NULL) *sgid = vu_uid_gid->sgid;
    if (fsgid != NULL) *fsgid = vu_uid_gid->fsgid;
    pthread_rwlock_unlock(&vu_uid_gid->lock);
  } else {
    if (fsgid != NULL)
      *fsgid = setfsgid(-1);
    getresgid(rgid, egid, sgid);
  }
  return 0;
}

int vu_unrealuidgid_getgroups(int size, gid_t list[], void *private) {
	int ret_value;
	if (vu_uid_gid != NULL) {
    pthread_rwlock_rdlock(&vu_uid_gid->lock);
		ret_value = vu_uid_gid->ngroups;
		if (size < vu_uid_gid->ngroups) {
			ret_value = -1;
			errno = EINVAL;
		} else
			memcpy(list, vu_uid_gid->groups, vu_uid_gid->ngroups * sizeof(gid_t));
		pthread_rwlock_unlock(&vu_uid_gid->lock);
		return ret_value;
	} else
		return getgroups(size, list);
}

int vu_unrealuidgid_setgroups(int size, const gid_t list[], void *private) {
	if (size < 0) {
		errno = EINVAL;
		return -1;
	}
	if (vu_uid_gid == NULL)
		vu_uid_gid_create();
  vu_uid_gid_modify_lock();
	vu_uid_gid->ngroups = size;
	vu_uid_gid->groups = realloc(vu_uid_gid->groups, vu_uid_gid->ngroups * sizeof(gid_t));
	memcpy(vu_uid_gid->groups, list, vu_uid_gid->ngroups * sizeof(gid_t));
	return 0;
}

static void *vu_uid_gid_clone(void *arg) {
	if (vu_uid_gid != NULL) {
		pthread_rwlock_wrlock(&vu_uid_gid->lock);
		vu_uid_gid->count++;
		pthread_rwlock_unlock(&vu_uid_gid->lock);
		return vu_uid_gid;
	} else
		return NULL;
}

static void vu_uid_gid_exec(void *arg) {
	 struct mod_inheritance_exec_arg *mod_exec = arg;
	 if (mod_exec->exec_uid != (uid_t) -1) {
		 uid_t setuid = mod_exec->exec_uid;
		 vu_unrealuidgid_setresfuid(-1, setuid, setuid, setuid, NULL);
		 mod_exec->exec_uid = (uid_t) -1;
	 }
	 if (mod_exec->exec_gid != (gid_t) -1) {
		 gid_t setgid = mod_exec->exec_gid;
     vu_unrealuidgid_setresfgid(-1, setgid, setgid, setgid, NULL);
     mod_exec->exec_gid = (gid_t) -1;
	 }
}

static void vu_uid_gid_terminate(void) {
	if (vu_uid_gid != NULL) {
		pthread_rwlock_wrlock(&vu_uid_gid->lock);
		vu_uid_gid->count -= 1;
		if (vu_uid_gid->count == 0) {
			struct vu_uid_gid_t *old_vu_uid_gid = vu_uid_gid;
			vu_uid_gid = NULL;
			pthread_rwlock_unlock(&old_vu_uid_gid->lock);
			pthread_rwlock_destroy(&old_vu_uid_gid->lock);
			free(old_vu_uid_gid);
		} else
			pthread_rwlock_unlock(&vu_uid_gid->lock);
	}
}

static void *vu_uid_gid_tracer_upcall(mod_inheritance_state_t state, void *arg) {
  void *ret_value = NULL;
  switch (state) {
    case MOD_INH_CLONE:
      ret_value = vu_uid_gid_clone(arg);
      break;
    case MOD_INH_START:
      vu_uid_gid = arg;
      break;
    case MOD_INH_EXEC:
      vu_uid_gid_exec(arg);
      break;
    case MOD_INH_TERMINATE:
      vu_uid_gid_terminate();
      break;
  }
  return ret_value;
}

static short vusc[]={
  __NR_getresuid, __NR_getresgid,
  __NR_setresuid, __NR_setresgid,
  __NR_setgroups,
  __NR_getgroups
};
#define VUSCLEN (sizeof(vusc) / sizeof(*vusc))
static struct vuht_entry_t *ht[VUSCLEN];

void *vu_unrealuidgid_init(void) {
  struct vu_service_t *s = vu_mod_getservice();
  unsigned int i;
  for (i = 0; i < VUSCLEN; i++) {
    int vu_syscall = vu_arch_table[vusc[i]];
    ht[i] = vuht_add(CHECKSC, &vu_syscall, sizeof(int), s, NULL, NULL, 0);
  }
	mod_inheritance_upcall_register(vu_uid_gid_tracer_upcall);
  return NULL;
}

int vu_unrealuidgid_fini(void *private) {
  unsigned int i;
  for (i = 0; i < VUSCLEN; i++) {
    if (ht[i] && vuht_del(ht[i], MNT_FORCE) == 0)
      ht[i] = NULL;
  }
	mod_inheritance_upcall_deregister(vu_uid_gid_tracer_upcall);
	return 0;
}
