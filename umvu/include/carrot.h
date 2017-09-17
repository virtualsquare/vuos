#ifndef CARROT_H
#define CARROT_H

#include <epoch.h>

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

