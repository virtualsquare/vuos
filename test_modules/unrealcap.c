/*
 *   VUOS: view OS project
 *   Copyright (C) 2019  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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

/* Usage example:
 *   $ vu_insmod unrealcap
 *   $ /sbin/capsh --caps=cap_chown+eip --
 *   $ /sbin/getpcaps $$
 *   Capabilities for `4855': = cap_chown+eip
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
#include <sys/capability.h>

VU_PROTOTYPES(unrealcap)

	struct vu_module_t vu_module = {
		.name = "unrealcap",
		.description = "virtualize capabilities"
	};

struct vu_cap_t {
	pid_t pid;
	struct __user_cap_data_struct data[2];
  struct vu_cap_t *next;
  struct vu_cap_t **pprev;
};

static pthread_rwlock_t vucap_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct vu_cap_t *vu_cap_head = NULL;
static __thread struct vu_cap_t *vu_cap = NULL;

static struct vu_cap_t *vu_cap_search(pid_t pid) {
	struct vu_cap_t *scan = vu_cap_head;
	while (scan != NULL) {
		if (scan->pid == pid)
			return scan;
		scan = scan->next;
	}
	return NULL;
}

int vu_unrealcap_capget(cap_user_header_t hdrp, cap_user_data_t datap) {
	struct vu_cap_t *this_cap = NULL;
	int retvalue;
	pthread_rwlock_rdlock(&vucap_lock);
	if (hdrp->pid == vu_mod_gettid())
		this_cap = vu_cap;
	else
		this_cap = vu_cap_search(hdrp->pid);
	if (this_cap == NULL)
		retvalue = capget(hdrp, datap);
	else {
		memcpy(datap, this_cap->data, sizeof(this_cap->data));
		retvalue = 0;
	}
	pthread_rwlock_unlock(&vucap_lock);
	return retvalue;
}

struct vu_cap_t *new_vu_cap(pid_t pid, cap_user_data_t datap) {
	struct vu_cap_t *this_cap = malloc(sizeof(struct vu_cap_t));
	if (this_cap == NULL)
		return NULL;
	else {
		this_cap->pid = pid;
		memcpy(this_cap->data, datap, sizeof(this_cap->data));
		pthread_rwlock_wrlock(&vucap_lock);
		this_cap->next = vu_cap_head;
		if (vu_cap_head != NULL)
			vu_cap_head->pprev = &(this_cap->next);
		this_cap->pprev = &vu_cap_head;
		vu_cap_head = this_cap;
		pthread_rwlock_unlock(&vucap_lock);
		return this_cap;
	}
}


int vu_unrealcap_capset(cap_user_header_t hdrp, cap_user_data_t datap) {
	if (vu_cap == NULL) {
		vu_cap = new_vu_cap(vu_mod_gettid(), datap);
		if (vu_cap == NULL)
			return errno = ENOMEM, -1;
		else
			return 0;
	} else {
		pthread_rwlock_wrlock(&vucap_lock);
		memcpy(vu_cap->data, datap, sizeof(vu_cap->data));
		pthread_rwlock_unlock(&vucap_lock);
		return 0;
	}
}

static void *vu_cap_clone(void *arg) {
	if (vu_cap != NULL) {
		return new_vu_cap(-1, vu_cap->data);
	} else
		return NULL;
}

static void vu_cap_start(void *arg) {
	vu_cap = arg;
	if (vu_cap != NULL)
		vu_cap->pid = vu_mod_gettid();
}

static void vu_cap_exec(void *arg) {
	 //struct mod_inheritance_exec_arg *mod_exec = arg; //Future management of security capability xattr
}

static void vu_cap_terminate(void) {
	if (vu_cap != NULL) {
		pthread_rwlock_wrlock(&vucap_lock);
		if (vu_cap->next != NULL)
			vu_cap->next->pprev = vu_cap->pprev;
		*(vu_cap->pprev) = vu_cap->next;
		free(vu_cap);
		vu_cap = NULL;
		pthread_rwlock_unlock(&vucap_lock);
	}
}

static void *vu_cap_tracer_upcall(mod_inheritance_state_t state, void *arg) {
  void *ret_value = NULL;
  switch (state) {
    case MOD_INH_CLONE:
      ret_value = vu_cap_clone(arg);
      break;
    case MOD_INH_START:
			vu_cap_start(arg);
      break;
    case MOD_INH_EXEC:
      vu_cap_exec(arg);
      break;
    case MOD_INH_TERMINATE:
      vu_cap_terminate();
      break;
  }
  return ret_value;
}

static short vusc[]={
  __NR_capget, __NR_capset,
};

#define VUSCLEN (sizeof(vusc) / sizeof(*vusc))
static struct vuht_entry_t *ht[VUSCLEN];

void *vu_unrealcap_init(void) {
  struct vu_service_t *s = vu_mod_getservice();
  unsigned int i;
  for (i = 0; i < VUSCLEN; i++) {
    int vu_syscall = vu_arch_table[vusc[i]];
    ht[i] = vuht_add(CHECKSC, &vu_syscall, sizeof(int), s, NULL, NULL, 0);
  }
	mod_inheritance_upcall_register(vu_cap_tracer_upcall);
  return NULL;
}

int vu_unrealcap_fini(void *private) {
  unsigned int i;
  for (i = 0; i < VUSCLEN; i++) {
    if (ht[i] && vuht_del(ht[i], MNT_FORCE) == 0)
      ht[i] = NULL;
  }
	mod_inheritance_upcall_deregister(vu_cap_tracer_upcall);
	return 0;
}
