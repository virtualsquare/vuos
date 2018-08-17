#ifndef VUFSTAT_H
#define VUFSTAT_H
#include<stdio.h>
#include<stdint.h>
#include<fcntl.h>
#include<vumodule.h>
#include<sys/types.h>
#include<sys/stat.h>

#define VUFSTAT_TYPE      0x00001
#define VUFSTAT_MODE      0x00002
#define VUFSTAT_UID       0x00010
#define VUFSTAT_GID       0x00020
#define VUFSTAT_RDEV      0x00100
#define VUFSTAT_DEV       0x00200
#define VUFSTAT_CTIME     0x01000
#define VUFSTAT_COPYMASK  (VUFSTAT_MODE | VUFSTAT_UID | VUFSTAT_GID)

uint32_t vufstat_merge(int dirfd, const char *path, struct vu_stat *statbuf);
uint32_t vufstat_cmpstat(struct vu_stat *statbuf1, struct vu_stat *statbuf2);
void vufstat_write(int dirfd, const char *path, struct vu_stat *statbuf, uint32_t mask);
void vufstat_update(int dirfd, const char *path, struct vu_stat *statbuf, uint32_t mask, mode_t creat);

#if 0
void vufstat_chmod(int dirfd, const char *path, mode_t mode);
void vufstat_chown(int dirfd, const char *path, uid_t owner, gid_t group);
void vufstat_mknod(int dirfd, const char *path, dev_t dev);
void vufstat_settype(int dirfd, const char *path, mode_t mode);
#endif
void vufstat_unlink(int dirfd, const char *path);
int vufstat_link(int dirfd, const char *oldpath, const char *newpath);
int vufstat_rename(int dirfd, const char *oldpath, const char *newpath, int flags);

#endif
