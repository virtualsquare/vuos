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

#include <pthread.h>
#include <vu_log.h>
#include <vu_thread_sd.h>
#include <vu_inheritance.h>

#include <umvu_peekpoke.h>
#include <vu_execute.h>

/* safe default value */
static struct syscall_extra_t default_extra;
static struct syscall_descriptor_t default_sd = {.extra = &default_extra};

/* per thread syscall descriptor */
__thread struct syscall_descriptor_t *thread_sd = &default_sd;

/* set the new value of sd and return the previous,
	 so that it can be used later to restore the old value */
struct syscall_descriptor_t *set_thread_sd(struct syscall_descriptor_t *sd) {
	struct syscall_descriptor_t *tmp = thread_sd;
	//printk("set_thread_sd (%d) %p->%p\n", umvu_gettid(), tmp, sd);
	thread_sd = sd;
	return tmp;
}

struct syscall_descriptor_t *get_thread_sd(void) {
	//printk("get_thread_sd (%d) %p\n", umvu_gettid(), thread_sd);
	return thread_sd;
}

static void *thread_sd_upcall(inheritance_state_t state, void *arg) {
  void *ret_value = NULL;
  switch (state) {
    case INH_PTHREAD_CLONE:
      ret_value = thread_sd;
			//printk("thread_sd_upcall CLONE %p\n", thread_sd);
      break;
    case INH_PTHREAD_START:
      thread_sd = arg;
			//printk("thread_sd_upcall START %p\n", thread_sd);
      break;
		default:
			break;
  }
  return ret_value;
}

__attribute__((constructor))
  static void init(void) {
    vu_inheritance_upcall_register(thread_sd_upcall);
  }

