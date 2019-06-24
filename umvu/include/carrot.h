#ifndef CARROT_H
#define CARROT_H

#include <epoch.h>

/* this is a helper module for hashtable.
	 Hashtable try to match incrementally the right module/service.
	 a match can be more specific (e.g. a subdirectory)
	 can have a more recent epoch and may have exceptions.
	 Checking for exceptions can be computationally expensive.
	 It is useless if the match is then overridden by a more specific,
	 more recent match.
	 So, the incremental matching process stores in a "carrot" the list of matches
	 that can have exceptions.
	 When the incremental matching process completes, the carrot contains all
	 the possible matches if the exceptions are confirmed or not. */

struct vuht_entry_t;
struct carrot_t;

/* Functions */
void carrot_free(struct carrot_t *old);
struct carrot_t *carrot_insert(struct carrot_t *head, struct vuht_entry_t *elem, epoch_t time,
		int (*has_exception)(struct vuht_entry_t *elem));
struct carrot_t *carrot_delete(struct carrot_t *head, struct vuht_entry_t *elem);
struct vuht_entry_t *carrot_check(struct carrot_t *head,
		int (*confirm)(struct vuht_entry_t *elem, void *opaque), void *opaque);

#endif

