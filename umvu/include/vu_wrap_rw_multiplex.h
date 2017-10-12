#ifndef VU_WRAP_RW_MULTIPLEX_H
#define VU_WRAP_RW_MULTIPLEX_H
#include <sys/stat.h>
#include <syscall_table.h>

void set_wi_read(mode_t mode, wrapf_t *handler);
void set_wd_read(mode_t mode, wrapf_t *handler);
void set_wo_read(mode_t mode, wrapf_t *handler);
void set_wi_write(mode_t mode, wrapf_t *handler);
void set_wd_write(mode_t mode, wrapf_t *handler);
void set_wo_write(mode_t mode, wrapf_t *handler);

#endif
