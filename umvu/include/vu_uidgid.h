#ifndef VU_UIDGID_H
#define VU_UIDGID_H


#include <sys/types.h>

void vu_uidgid_getresfuid(uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid);
void vu_uidgid_setresfuid(const uid_t ruid, const uid_t euid, const uid_t suid, const uid_t fsuid);
void vu_uidgid_getresfgid(gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid);
void vu_uidgid_setresfgid(const gid_t rgid, const gid_t egid, const gid_t sgid, const gid_t fsgid);
int vu_uidgid_getgroups(int size, gid_t list[]);
int vu_uidgid_setgroups(int size, gid_t list[]);

#endif
