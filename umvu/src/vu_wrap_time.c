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
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <syscall_defs.h>
#include <xcommon.h>
#include <hashtable.h>
#include <service.h>
#include <epoch.h>
#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <vu_wrapper_utils.h>
#include <vu_execute.h>

void wi_clock_gettime(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		sd->action = SKIPIT;
		switch (sd->syscall_number) {
			case __NR_clock_gettime:
				{
					clockid_t clk_id = sd->syscall_args[0];
					uintptr_t tpaddr = sd->syscall_args[1];
					if (tpaddr == 0)
						sd->ret_value = EFAULT;
					else {
						struct timespec *tp;
						vu_alloc_local_arg(tpaddr, tp, sizeof(*tp), nested);
						sd->ret_value = service_syscall(ht, __VU_clock_gettime)(clk_id, tp);
						if (sd->ret_value == 0)
							vu_poke_arg(tpaddr, tp, sizeof(*tp), nested);
					}
				}
				break;
			case __NR_gettimeofday:
				{
					/* timezone is obsolete. ignored here */
					uintptr_t tvaddr = sd->syscall_args[0];
					if (tvaddr == 0)
            sd->ret_value = EFAULT;
          else {
						struct timespec tp;
						struct timeval *tv;
						vu_alloc_local_arg(tvaddr, tv, sizeof(*tv), nested);
						sd->ret_value = service_syscall(ht, __VU_clock_gettime)(CLOCK_REALTIME, &tp);
						tv->tv_sec = tp.tv_sec;
						tv->tv_usec = tp.tv_nsec / 1000;
						if (sd->ret_value == 0)
              vu_poke_arg(tvaddr, tv, sizeof(*tv), nested);
					}
				}
				break;
			case __NR_time:
				{
					uintptr_t timeaddr = sd->syscall_args[0];
					struct timespec tp;
					sd->ret_value = service_syscall(ht, __VU_clock_gettime)(CLOCK_REALTIME, &tp);
					if (sd->ret_value == 0)
						sd->ret_value = tp.tv_sec;
					if (timeaddr != 0) {
						time_t *now;
						vu_alloc_local_arg(timeaddr, now, sizeof(*now), nested);
						*now = tp.tv_sec;
					}
				}
				break;
		}
	}
}

void wi_clock_settime(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		sd->action = SKIPIT;
		switch (sd->syscall_number) {
			case __NR_clock_settime:
				{
					clockid_t clk_id = sd->syscall_args[0];
					uintptr_t tpaddr = sd->syscall_args[1];
					if (tpaddr == 0)
						sd->ret_value = EFAULT;
					else {
						struct timespec *tp;
						vu_alloc_peek_local_arg(tpaddr, tp, sizeof(*tp), nested);
						sd->ret_value = service_syscall(ht, __VU_clock_settime)(clk_id, tp);
					}
				}
				break;
			case __NR_settimeofday:
				{
					/* timezone is obsolete. ignored here */
          uintptr_t tvaddr = sd->syscall_args[0];
          if (tvaddr == 0)
            sd->ret_value = EFAULT;
          else {
            struct timespec tp;
            struct timeval *tv;
            vu_alloc_peek_local_arg(tvaddr, tv, sizeof(*tv), nested);
						tp.tv_sec = tv->tv_sec;
						tp.tv_nsec = tv->tv_usec * 1000;
						sd->ret_value = service_syscall(ht, __VU_clock_settime)(CLOCK_REALTIME, &tp);
					}
				}
		}
	}
}

void wi_clock_getres(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	  int nested = sd->extra->nested;
  if (ht) {
		uintptr_t tpaddr = sd->syscall_args[1];
		if (tpaddr == 0)
			sd->ret_value = EFAULT;
		else {
			clockid_t clk_id = sd->syscall_args[0];
			uintptr_t tpaddr = sd->syscall_args[1];
			if (tpaddr == 0)
				sd->ret_value = EFAULT;
			else {
				struct timespec *tp;
				vu_alloc_local_arg(tpaddr, tp, sizeof(*tp), nested);
				sd->ret_value = service_syscall(ht, __VU_clock_getres)(clk_id, tp);
				if (sd->ret_value == 0)
					vu_poke_arg(tpaddr, tp, sizeof(*tp), nested);
			}
		}
	}
}

