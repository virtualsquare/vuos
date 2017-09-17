#ifndef _EPOCH_H
#define _EPOCH_H
#include <stdint.h>

/*
 * Each node is timestamped with its starting epoch.
 * After each relevant operation the timestamp is updated.
 */

typedef uint64_t epoch_t;

/* function definitions */
void update_vepoch();
epoch_t set_vepoch(epoch_t e);
epoch_t get_vepoch();
epoch_t get_epoch();
epoch_t update_epoch();
epoch_t matching_epoch(epoch_t service_epoch);

#endif

