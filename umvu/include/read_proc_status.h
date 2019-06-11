#ifndef READ_PROC_STATUS_H
#define READ_PROC_STATUS_H
#include <stdio.h>
#include <unistd.h>

/* this module uses /proc/###/status to get the following information about
	 the user-thread corresponging to the calling thread (the "protected" thread of
	 the calling "guardian angel"):
	 real, effective, saved, filesystem user id
	 real, effective, saved, filesystem group id
	 the list of the groups */
/* NB XXX this module could be reimplemented by keeping track of all the successful
	 changes acknowledged by the kernel */
void status_getresfuid(pid_t tid, uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid);
void status_getresfgid(pid_t tid, gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid);
int status_getgroups(pid_t tid, int size, gid_t list[]);

#endif
