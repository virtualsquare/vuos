#ifndef VUFS_GETDENTS_H
#define VUFS_GETDENTS_H

struct vufs_t;

int vufs_enotempty_ck(struct vufs_t *vufs, const char *path);

#endif
