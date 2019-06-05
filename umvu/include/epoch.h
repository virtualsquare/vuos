#ifndef _EPOCH_H
#define _EPOCH_H
#include <stdint.h>

/*
 * Each node is timestamped with its starting epoch.
 * After each relevant operation the timestamp is updated.
 *
 * Epoch is the key concept for layered virtualization.
 * each system call request generated inside the hypervisor
 * (guardian angels, helper threads) happens at the epoch
 * when that virtualization was activated (e.g. the epoch
 * when a file system was mounted). In this way these system
 * calls see the world at that time, and cen be further
 * virtualized.
 *
 * e.g. mount a file system in /mnt at epoch 42
 *      mount the file system image /mnt/image on /mnt at epoch 44
 *      open (/mnt/myfile) at epoch 50.
 * /mnt/myfile is in the subtree virtualized by the mount at epoch 44.
 * the virtualization module (e.g. vufuse) processing the 'open' request
 * runs at epoch 44, so if it needs to run a system call (say
 * lstat("/mnt/test"...), the request is managed by the virtualization
 * aptivated by the "mount" at epoch 42 (at epoch 44 the second "mount"
 * did not exist).
 */

typedef uint64_t epoch_t;

/* function definitions */

/* a relevant event happened. epoch is incremented by one tick */
void update_vepoch(void);

/* define a new working/virtual epoch for the current thread,
	 it returns the previous epoch (to restore the value in a second time */
epoch_t set_vepoch(epoch_t e);

/* return the working/virtual epoch for the current thread, */
epoch_t get_vepoch(void);

/* return the current (global) epoch, the *now* epoch */
epoch_t get_epoch(void);

/* set the current (global) epoch, to the current/global/ *now* epoch */
epoch_t update_epoch(void);

/* return the service_epoch if it is consistent with the current
	 working/virtual epoch of calling thread.
	 It returns 0 if service_epoch is too new, so this
	 'service'/virtualization did not exist at the current/working/virtual epoch */
epoch_t matching_epoch(epoch_t service_epoch);

#endif

