#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/sysmacros.h>
#include<stropt.h>
#include<strcase.h>
#include<vustat.h>

#define VSTATBUFLEN 1024
#define ARGMAXLEN 16
#define NELEM(X) (sizeof(X)/sizeof(*(X)))
static int vustat_open(int dirfd, char *path, int flags) {
	int pathlen = strlen(path) + 2;
	char vstatpath[pathlen];
	snprintf(vstatpath, pathlen, "%s%c", path, 127);
	if (flags == O_EXCL)
		return unlinkat(dirfd, vstatpath, 0);
	else
		return openat(dirfd, vstatpath, flags, 0777);
}

static void vustat_read(int vstatfd, char *buf, size_t size) {
	ssize_t n = read(vstatfd, buf, size - 1);
	if (n < 0) n = 0;
	buf[n] = 0;
}

static inline int vustat_stropt(const char *input, char **tags, char **args, char *buf) {
	return stroptx(input, NULL, "\n", 0, tags, args, buf);
}

void vustat_merge(int dirfd, char *path, struct stat *statbuf) {
	int vstatfd = vustat_open(dirfd, path, O_RDONLY);
	if (vstatfd >= 0) {
		char input[VSTATBUFLEN];
		int tagc;
		vustat_read(vstatfd, input, VSTATBUFLEN);
		close(vstatfd);
		tagc = vustat_stropt(input, NULL, NULL, 0);
		if(tagc > 0) {
			char *tags[tagc];
			char *args[tagc];
			vustat_stropt(input, tags, args, input);
			for (int i = 0; tags[i]; i++) {
				if (args[i] != NULL) {
					switch (strcase(tags[i])) {
						case(STRCASE(u,i,d)) : statbuf->st_uid = strtoul(args[i], NULL, 0);
																	 break;
						case(STRCASE(g,i,d)) : statbuf->st_gid = strtoul(args[i], NULL, 0);
																	 break;
						case(STRCASE(m,a,j,o,r)) : statbuf->st_rdev = makedev(strtoul(args[i], NULL, 0), minor(statbuf->st_rdev));
																			 break;
						case(STRCASE(m,i,n,o,r)) : statbuf->st_rdev = makedev(major(statbuf->st_rdev), strtoul(args[i], NULL, 0));
																			 break;
						case(STRCASE(m,o,d,e)) : statbuf->st_mode = (statbuf->st_mode & S_IFMT) | (strtoul(args[i], NULL, 8) & ~S_IFMT);
																		 break;
					}
				}
				//printf("%s = %s\n",tags[i], args[i]);
			}
		}
	}
}

static void vustat_set(int dirfd, char *path, char **ntags, char **nargs, int ntagc) {
	int vstatfd = vustat_open(dirfd, path, O_RDWR | O_CREAT);
	if (vstatfd >= 0) {
    char input[VSTATBUFLEN];
		char *output;
    int tagc;
    vustat_read(vstatfd, input, VSTATBUFLEN);
		//printf("input %s\n", input);
    tagc = vustat_stropt(input, NULL, NULL, 0);
		if(tagc + ntagc > 0) {
			char *tags[tagc + ntagc];
			char *args[tagc + ntagc];
			int i, j;
			if (tagc > 0) {
				vustat_stropt(input, tags, args, input);
				for (i = 0; tags[i]; i++) {
					for (j = 0; j < ntagc && tags[i] != STROPTX_DELETED_TAG; j++) {
						 if (ntags[j] != STROPTX_DELETED_TAG && strcmp(tags[i], ntags[j]) == 0)
							 tags[i] = STROPTX_DELETED_TAG;
					}
				}
			} else 
				i = 0;
			for (j = 0; j < ntagc; i++, j++) {
				tags[i] = ntags[j];
				args[i] = nargs[j];
			}
			tags[i] = NULL;
			args[i] = NULL;
			output = stropt2str(tags, args, '\n', '=');
			if (output != NULL) {
				ftruncate(vstatfd, 0);
				lseek(vstatfd, 0, SEEK_SET);
				write(vstatfd, output, strlen(output));
				write(vstatfd, "\n", 1);
				free(output);
			}
		}
		close(vstatfd);
	}
}

void vustat_chmod(int dirfd, char *path, mode_t mode) {
	char mode_s[ARGMAXLEN];
	char *tags[] = {"mode"};
	char *args[] = {mode_s};
	snprintf(mode_s, ARGMAXLEN, "0%o", mode & ~S_IFMT);
	vustat_set(dirfd, path, tags, args, NELEM(tags));
}

void vustat_chown(int dirfd, char *path, uid_t owner, gid_t group) {
	char uid_s[ARGMAXLEN];
	char gid_s[ARGMAXLEN];
	char *tags[] = {"uid", "gid"};
  char *args[] = {uid_s, gid_s};
	if (owner != (uid_t) -1)
		snprintf(uid_s, ARGMAXLEN, "%d", owner);
	else
		tags[0] = STROPTX_DELETED_TAG;
	if (group != (gid_t) -1)
		snprintf(gid_s, ARGMAXLEN, "%d", group);
	else
		tags[1] = STROPTX_DELETED_TAG;
  vustat_set(dirfd, path, tags, args, NELEM(tags));

}

void vustat_mknod(int dirfd, char *path, dev_t dev) {
	char major_s[ARGMAXLEN];
	char minor_s[ARGMAXLEN];
	char *tags[] = {"major", "minor"};
  char *args[] = {major_s, minor_s};
	snprintf(major_s, ARGMAXLEN, "%d", major(dev));
	snprintf(minor_s, ARGMAXLEN, "%d", minor(dev));
  vustat_set(dirfd, path, tags, args, NELEM(tags));
}

void vustat_unlink(int dirfd, char *path) {
	vustat_open(dirfd, path, O_EXCL);
}

#if 0
int main(int argc, char *argv[]) {
	int dirfd = open(argv[1], O_PATH);
	//vustat_merge(dirfd, argv[2], NULL);
	vustat_chown(dirfd, argv[2], 1000, 1001);
	vustat_chmod(dirfd, argv[2], 02755);
	vustat_chmod(dirfd, argv[2], 01700);
	vustat_mknod(dirfd, argv[2], 05555);
	vustat_chown(dirfd, argv[2], 1100, 1200);
	//vustat_unlink(dirfd, argv[2]);
}
#endif
