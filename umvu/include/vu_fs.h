#ifndef FS_H
#define FS_H

void vu_fs_set_cwd(char *wd);
void vu_fs_set_rootdir(char *dir);
mode_t vu_fs_set_umask(mode_t mask);

void vu_fs_get_rootdir(char *dest, size_t n);
int vu_fs_is_chroot(void);
void vu_fs_get_cwd(char *dest, size_t n);
mode_t vu_fs_get_umask(void);

#endif
