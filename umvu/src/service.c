#include <service.h>

static __thread struct vuht_entry_t *thread_private_ht_for_modules;

void vu_mod_setht(struct vuht_entry_t *ht) {
	thread_private_ht_for_modules = ht;
}

struct vuht_entry_t *vu_mod_getht(void) {
	return thread_private_ht_for_modules;
}
