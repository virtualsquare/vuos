#ifndef FS_H
#define FS_H

/* file system module. This module keep track of:
 *     current working directory
 *     chroot
 *     umask
 * it automatically manages: clone/fork, termination of user-threads and hypervisor threads.
 * (info are shared if clone has the flag CLONE_FS set).
 */

/* change the working directory */
void vu_fs_set_cwd(char *wd);
/* change the root directory */
void vu_fs_set_rootdir(char *dir);
/* change the umask directory: return the previous mask */
mode_t vu_fs_set_umask(mode_t mask);

/* helper functions */

void vu_fs_get_rootdir(char *dest, size_t n);
int vu_fs_is_chroot(void);
void vu_fs_get_cwd(char *dest, size_t n);
mode_t vu_fs_get_umask(void);

#endif
