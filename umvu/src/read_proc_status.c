#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <read_proc_status.h>

#define STATUS_PATH_FORMAT "/proc/%d/status"
#define STATUS_PATH_SIZE sizeof(STATUS_PATH_FORMAT) + sizeof(pid_t) * 3
char *getlinetag(pid_t tid, char *tag) {
	char path[STATUS_PATH_SIZE];
	size_t taglen = strlen(tag);
	snprintf(path, STATUS_PATH_SIZE, STATUS_PATH_FORMAT, tid);

	FILE *status_file = fopen(path, "r");
	if (status_file) {
		char *line = NULL ;
		size_t len = 0;
		while (getline(&line, &len, status_file) > 0) {
			if (strncmp(line, tag, taglen) == 0 && line[taglen] == ':') {
				fclose(status_file);
				return line;
			}
		}
		fclose(status_file);
		free(line);
	}
	return NULL;
}

void status_getresfuid(pid_t tid, uid_t *ruid, uid_t *euid, uid_t *suid, uid_t *fsuid) {
	char *uidline = getlinetag(tid, "Uid");
	if (uidline) {
		char *s = uidline +  4;
    *ruid = strtoul(s, &s, 0);
    *euid = strtoul(s, &s, 0);
    *suid = strtoul(s, &s, 0);
    *fsuid = strtoul(s, &s, 0);
    free(uidline);
	} else
		*ruid = *euid = *suid = *fsuid = (uid_t) -1;
}

void status_getresfgid(pid_t tid, gid_t *rgid, gid_t *egid, gid_t *sgid, gid_t *fsgid) {
  char *gidline = getlinetag(tid, "Gid");
  if (gidline) {
		char *s = gidline +  4;
    *rgid = strtoul(s, &s, 0);
    *egid = strtoul(s, &s, 0);
    *sgid = strtoul(s, &s, 0);
    *fsgid = strtoul(s, &s, 0);
    free(gidline);
  } else
    *rgid = *egid = *sgid = *fsgid = (gid_t) -1;
}

int status_getgroups(pid_t tid, int size, gid_t list[]) {
	char *groupsline = getlinetag(tid, "Groups");
	if (groupsline) {
		    char *s;
    int n;
    for (s = groupsline + 7, n = 0; *s != '\0'; n++, s += strspn(s, " \t\n")) {
      unsigned long g = strtoul(s, &s, 0);
      if (size != 0) {
        if (n < size)
          list[n] = g;
        else
          break;
      }
    }
    free(groupsline);
    return (*s == '\0') ? n : -1;
	}
	else
		return -1;
}

#if 0
int main(int argc, char *argv[]) {
	uid_t ruid, euid, suid, fsuid;
	status_getresfuid(atoi(argv[1]), &ruid, &euid, &suid, &fsuid);
	printf("%d %d %d %d\n", ruid, euid, suid, fsuid);
	gid_t rgid, egid, sgid, fsgid;
	status_getresfgid(atoi(argv[1]), &rgid, &egid, &sgid, &fsgid);
	printf("%d %d %d %d\n", rgid, egid, sgid, fsgid);
	int size;
	if ((size = status_getgroups(atoi(argv[1]), 0, NULL)) > 0) {
		int i;
		gid_t list[size];
		status_getgroups(atoi(argv[1]), size, list);
		for(i = 0; i< size; i++)
			printf("%d ", list[i]);
		printf("\n");
	}
}
#endif
