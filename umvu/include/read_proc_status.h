#ifndef READ_PROC_STATUS_H
#define READ_PROC_STATUS_H
#include <stdio.h>
#include <unistd.h>

/**Accessing directly the /proc/%d/status file, it can only be red not written.*/
// real effective saved filesystem 
void status_getresfuid(pid_t tid, uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid);
void status_getresfgid(pid_t tid, gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid);
int status_getgroups(pid_t tid, int size, gid_t list[]);

#endif
