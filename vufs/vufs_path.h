#ifndef VUFS_PATH_H
#define VUFS_PATH_H

typedef void (*create_path_cb_t)(void *arg, int dirfd, const char *path);

void vufs_create_path(int dirfd, const char *path, create_path_cb_t callback, void *arg);
void vufs_destroy_path(int dirfd, const char *path);
void vufs_destroy_tree(int dirfd, const char *path, int recursive);
int vufs_whiteout(int dirfd, const char *path);
void vufs_dewhiteout(int dirfd, const char *path);

#endif
