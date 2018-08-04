#ifndef VUSTAT_H
#define VUSTAT_H
#include<stdio.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>

void vustat_merge(int dirfd, char *path, struct stat *statbuf);
void vustat_chmod(int dirfd, char *path, mode_t mode);
void vustat_chown(int dirfd, char *path, uid_t owner, gid_t group);
void vustat_mknod(int dirfd, char *path, dev_t dev);
void vustat_unlink(int dirfd, char *path);

#endif
