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

