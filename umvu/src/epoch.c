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
#include <stdint.h>
#include <epoch.h>

/* per thread time keeping */
__thread epoch_t virtual_epoch;
/* epoch now is a (uint64_t) counter, it is used to timestamp all the state
 * changes in the system */
static epoch_t epoch_now = 2;

/* one tick of the global timestap clock epoch_now */
epoch_t update_epoch()
{
	return __sync_fetch_and_add(&epoch_now, 1);
}

epoch_t set_vepoch(epoch_t e)
{
	epoch_t tmp = virtual_epoch;
	virtual_epoch = e;
	return tmp;
}

epoch_t get_epoch()
{
	return __sync_fetch_and_add(&epoch_now, 0);
}

void update_vepoch()
{
	virtual_epoch = __sync_fetch_and_add(&epoch_now, 0);
}

epoch_t get_vepoch()
{
	return virtual_epoch;
}

/* it is > 0 if the operation time is consistent with the service time.
 * in such a case it returns the epoch of the matching */
epoch_t matching_epoch(epoch_t service_epoch)
{
	if (service_epoch < virtual_epoch)
		return service_epoch;
	else
		return 0;
}

