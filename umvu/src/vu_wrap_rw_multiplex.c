#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <xstat.h>
#include <syscall_table.h>
#include <vu_execute.h>

wrapf_t wi_NULL, wd_NULL, wo_NULL;
static wrapf_t wi_einval;
static wrapf_t *x_wi_read[S_TYPES] = {S_TYPES_INIT(wi_einval)};
static wrapf_t *x_wd_read[S_TYPES] = {S_TYPES_INIT(wd_NULL)};
static wrapf_t *x_wo_read[S_TYPES] = {S_TYPES_INIT(wo_NULL)};
static wrapf_t *x_wi_write[S_TYPES] = {S_TYPES_INIT(wi_einval)};
static wrapf_t *x_wd_write[S_TYPES] = {S_TYPES_INIT(wd_NULL)};
static wrapf_t *x_wo_write[S_TYPES] = {S_TYPES_INIT(wo_NULL)};

static void wi_einval(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht != NULL) {
		sd->ret_value = -EINVAL;
		sd->action = SKIPIT;
	}
}

void set_wi_read(mode_t mode, wrapf_t *handler) {
	x_wi_read[S_MODE2TYPE(mode)] = handler;
}

void set_wd_read(mode_t mode, wrapf_t *handler) {
	x_wd_read[S_MODE2TYPE(mode)] = handler;
}

void set_wo_read(mode_t mode, wrapf_t *handler) {
	x_wo_read[S_MODE2TYPE(mode)] = handler;
}

void set_wi_write(mode_t mode, wrapf_t *handler) {
	x_wi_write[S_MODE2TYPE(mode)] = handler;
}

void set_wd_write(mode_t mode, wrapf_t *handler) {
	x_wd_write[S_MODE2TYPE(mode)] = handler;
}

void set_wo_write(mode_t mode, wrapf_t *handler) {
	x_wo_write[S_MODE2TYPE(mode)] = handler;
}

void wi_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wi_read[S_MODE2TYPE(mode)](ht, sd);
}

void wi_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wi_write[S_MODE2TYPE(mode)](ht, sd);
}

void wd_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wd_read[S_MODE2TYPE(mode)](ht, sd);
}

void wd_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wd_write[S_MODE2TYPE(mode)](ht, sd);
}

void wo_read(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wo_read[S_MODE2TYPE(mode)](ht, sd);
}

void wo_write(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	mode_t mode = sd->extra->statbuf.st_mode;
	x_wo_write[S_MODE2TYPE(mode)](ht, sd);
}

