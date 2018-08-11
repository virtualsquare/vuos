/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <vumodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <volatilestream.h>
#include <pthread.h>
#include <strcase.h>
#include <stropt.h>
#include <vustat.h>

VU_PROTOTYPES(vufs)

#define VUFS_MERGE 0x1
#define VUFS_COW 0x2
#define VUFS_MINCOW 0x4
#define VUFS_RDONLY 0x8
#define VUFS_VSTAT 0x100

struct vufs_t {
	pthread_mutex_t mutex;

	char *source;
	char *target;
	int rdirfd;
	int vdirfd;
	int ddirfd;
	int flags;

	char *except[];
};

struct vufs_fdprivate {
	FILE *getdentsf;
	char path[];
};

static void create_path(int dirfd, char *path) {
	int pathlen = strlen(path);
	char tpath[pathlen];
	int i;
	for (i = 0; i < pathlen; i++) {
		if (path[i] == '/') {
			tpath[i] = 0;
			mkdirat(dirfd, tpath, 0777);
		}
		tpath[i] = path[i];
	}
}

static void destroy_path(int dirfd, char *path) {
	int pathlen = strlen(path);
  char tpath[pathlen];
	int i;
	strncpy(tpath, path, pathlen);
	for (i = pathlen - 1; i >= 0; i--) {
		if (tpath[i] == '/') {
			tpath[i] = 0;
			if (unlinkat(dirfd, tpath, AT_REMOVEDIR) < 0)
				break;
		}
	}
}

#define CHUNKSIZE 4096
static int copyfile(int srcdirfd, int dstdirfd, char *path, size_t truncate) {
	int fdin = openat(srcdirfd, path, O_RDONLY, 0);
	int fdout = openat(dstdirfd, path, O_WRONLY | O_CREAT | O_TRUNC, 0, 0777);
	if (fdin >= 0 && fdout >= 0) {
		size_t nread, readsize = CHUNKSIZE; 
		char buf[CHUNKSIZE];
		while (1) {
			if (truncate < readsize) readsize = truncate;
			nread = read(fdin, buf, readsize);
			if (nread <= 0)
				break;
			truncate -= nread;
			nread = write(fdout, buf, nread);
			if (nread <= 0)
				break;
		}
		close(fdin);
		close(fdout);
		return nread == 0 ? 0 : -1;
	} else {
		if (fdin >= 0) close(fdin);
		if (fdout >= 0) close(fdout);
		errno = EIO;
		return -1;
	}
}
static int vufs_vdeleted(struct vufs_t *vufs, const char *path) {
	struct vu_stat buf;
	if (vufs->ddirfd >= 0)
		return fstatat(vufs->ddirfd, path, &buf, AT_EMPTY_PATH) == 0 && S_ISREG(buf.st_mode);
	else
		return 0;
}

int vu_vufs_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	int vdeleted;
	pthread_mutex_lock(&(vufs->mutex));
	vdeleted = vufs_vdeleted(vufs, pathname + 1);
  retval = fstatat(vufs->vdirfd, pathname + 1, buf, flags | AT_EMPTY_PATH);
	if (retval < 0  && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = fstatat(vufs->rdirfd, pathname + 1, buf, flags | AT_EMPTY_PATH);
	if (retval == 0)
		 vustat_merge(vufs->ddirfd, pathname + 1, buf);
	pthread_mutex_unlock(&(vufs->mutex));
	printkdebug(V, "LSTAT path:%s retvalue:%d", pathname + 1, retval);
	return retval;
}

int vu_vufs_access(char *path, int mode, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	int vdeleted;
	pthread_mutex_lock(&(vufs->mutex));
	vdeleted = vufs_vdeleted(vufs, path + 1);
	retval = faccessat(vufs->vdirfd, path + 1, mode, flags | AT_EMPTY_PATH);
	if (retval < 0  && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = faccessat(vufs->rdirfd, path + 1, mode, flags | AT_EMPTY_PATH);
	pthread_mutex_unlock(&(vufs->mutex));
	printkdebug(V,"ACCESS path:%s mode:%o retvalue:%d", path, mode, retval);
	return retval;
}

int vu_vufs_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return fchownat(vufs->vdirfd, pathname + 1, owner, group, AT_EMPTY_PATH /* XXX */);
}

int vu_vufs_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return fchmodat(vufs->vdirfd, pathname + 1, mode, AT_EMPTY_PATH /* XXX */);
}

ssize_t vu_vufs_readlink(char *path, char *buf, size_t bufsiz) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	//printk("vu_vufs_readlink %s\n", path);
	return readlinkat(vufs->vdirfd, path + 1, buf, bufsiz);
}

#if 0
int vu_vufs_statfs (const char *pathname, struct statfs *buf, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return -1;
}
#endif

int vu_vufs_unlink (const char *pathname) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return unlinkat(vufs->vdirfd, pathname + 1, AT_EMPTY_PATH);
}

int vu_vufs_mkdir (const char *pathname, mode_t mode) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return mkdirat(vufs->vdirfd, pathname + 1, mode);
}

int vu_vufs_mknod (const char *pathname, mode_t mode, dev_t dev) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return mknodat(vufs->vdirfd, pathname + 1, mode, dev);
}

int vu_vufs_rmdir(const char *pathname) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return unlinkat(vufs->vdirfd, pathname + 1, AT_REMOVEDIR);
}

#if 0
int vu_vufs_truncate(const char *path, off_t length, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return -1;
}
#endif

int vu_vufs_link (const char *target, const char *linkpath) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return linkat(vufs->vdirfd, target + 1, vufs->vdirfd, linkpath + 1, 0 /* XXX */);
}

int vu_vufs_symlink (const char *target, const char *linkpath) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return symlinkat(target,  vufs->vdirfd, linkpath + 1);
}

int vu_vufs_rename (const char *target, const char *linkpath, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	return syscall(__NR_renameat2, vufs->vdirfd, target + 1, vufs->vdirfd, linkpath + 1, flags);
}

int vu_vufs_open(const char *pathname, int flags, mode_t mode, void **private) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int vdeleted = 0;
	const char *filepath;
	int retval;
	pathname++;
	filepath = pathname;
	pthread_mutex_lock(&(vufs->mutex));
	/* unfortunately AT_EMPTY_PATH is not supported by openat */
	if (*filepath == 0) 
		filepath = vufs->source;
	else
		vdeleted = vufs_vdeleted(vufs, filepath);
	retval = openat(vufs->vdirfd, filepath, flags, mode);
	if (retval < 0 && errno == ENOENT && vufs->rdirfd >= 0 && !vdeleted)
		retval = openat(vufs->rdirfd, pathname, flags, mode);
	if (retval >= 0) {
		int pathlen = strlen(pathname) + 1;
		struct vufs_fdprivate *vufs_fdprivate = 
			malloc(sizeof(struct vufs_fdprivate) + pathlen);
		vufs_fdprivate->getdentsf = NULL;
		strncpy(vufs_fdprivate->path, pathname, pathlen);
		*private = vufs_fdprivate;
	} else
		*private = NULL;
	pthread_mutex_unlock(&(vufs->mutex));
	return retval;
}

int vu_vufs_close(int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	pthread_mutex_lock(&(vufs->mutex));
	retval = close(fd);
	if (retval == 0 && fdprivate != NULL) {
		struct vufs_fdprivate *vufs_fdprivate = fdprivate;
		if (vufs_fdprivate->getdentsf != NULL)
			fclose(vufs_fdprivate->getdentsf);
		free(vufs_fdprivate);
	}
	pthread_mutex_unlock(&(vufs->mutex));
	return retval;
}

/* Support of directory merging */

/* add an entry to the volatile stream for getdents */
static int vufs_filldir_entry(FILE *f, const char *name, unsigned char type, __ino64_t ino) {
  struct dirent64 entry = {
    .d_ino = ino,
    .d_type = type,
    .d_off = ftello(f),
  };
  static char filler[7];
  unsigned short int namelen = strlen(name) + 1;
  unsigned short int reclen  = offsetof(struct dirent64, d_name) + namelen;
  int ret_value;
  snprintf(entry.d_name, 256, "%s", name);
  /* entries are always 8 bytes aligned */
  entry.d_reclen = (reclen + 7) & (~7);
  ret_value = fwrite(&entry, reclen, 1, f);
  /* add a filler to align the next entry */
  if (entry.d_reclen > reclen)
    ret_value += fwrite(filler, entry.d_reclen - reclen, 1, f);
  return 0;
}

/* check if a name is in the list of already seen names*/
/* the "list" is a concatenation of zero terminated strings.
	 an empty entry is the tag of the end of list */
static int vufs_seen_entry(char *s, char *list) {
	char *scan = list;
  while (*scan) {
		if (strcmp(s, scan) == 0)
			return 1;
    scan += strlen(scan) + 1;
  }
	return 0;
}

static void vufs_filldir(unsigned int fd, struct vufs_t *vufs, struct vufs_fdprivate *vufs_fdprivate) {
	char *seenlist = NULL;
	size_t seenlistlen = 0;
	FILE *seenf = open_memstream(&seenlist, &seenlistlen);
	DIR *dir;
	struct dirent *de;
	vufs_fdprivate->getdentsf = volstream_open();
	dir = fdopendir(dup(fd));
	if (dir) {
		int dirfd;
		/* ADD entries in vdirfd (source) */
		while ((de = readdir(dir)) != NULL) {
			if (!(vufs_fdprivate->path[0] == 0 && strcmp(de->d_name, ".-") == 0)) {
				vufs_filldir_entry(vufs_fdprivate->getdentsf, de->d_name, de->d_type, de->d_ino);
				if (vufs->rdirfd >= 0)
					fwrite(de->d_name, strlen(de->d_name) + 1, 1, seenf);
			}
		}
		closedir(dir);
		if (vufs->rdirfd >= 0) {
			/* ADD deleted entries (ddirfd) in seenlist (if merge) */
			if (vufs->ddirfd >= 0) {
				if (vufs_fdprivate->path[0] == 0)
					dirfd = openat(vufs->vdirfd, ".-", O_RDONLY | O_DIRECTORY);
				else
					dirfd = openat(vufs->ddirfd, vufs_fdprivate->path, O_RDONLY | O_DIRECTORY);
				if (dirfd >= 0) {
					dir = fdopendir(dirfd);
					while ((de = readdir(dir)) != NULL)
						fwrite(de->d_name, strlen(de->d_name) + 1, 1, seenf);
					closedir(dir);
				}
			}
			/* write the empty string as the end of the seen list */
			fwrite("", 1, 1, seenf);
			fflush(seenf);
			/* ADD unseen entries in rdirfd (target) (if merge) */
			if (vufs_fdprivate->path[0] == 0)
				dirfd = openat(vufs->rdirfd, vufs->target, O_RDONLY | O_DIRECTORY);
			else
				dirfd = openat(vufs->rdirfd, vufs_fdprivate->path, O_RDONLY | O_DIRECTORY);
			if (dirfd >= 0) {
				dir = fdopendir(dirfd);
				while ((de = readdir(dir)) != NULL) {
					if (! vufs_seen_entry(de->d_name, seenlist))
						vufs_filldir_entry(vufs_fdprivate->getdentsf, de->d_name, de->d_type, de->d_ino);
				}
				closedir(dir);
			}
		}
	}
	fclose(seenf);
	if (seenlist != NULL)
		free(seenlist);
	fseeko(vufs_fdprivate->getdentsf, 0, SEEK_SET);
}

int vu_vufs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	if (fdprivate != NULL) {
		int retval;
		pthread_mutex_lock(&(vufs->mutex));
		struct vufs_fdprivate *vufs_fdprivate = fdprivate;
		if (vufs_fdprivate->getdentsf == NULL)
			vufs_filldir(fd, vufs, vufs_fdprivate);
		if (vufs_fdprivate->getdentsf != NULL) {
			retval = fread(dirp, 1, count, vufs_fdprivate->getdentsf);
			if (retval == (int) count) {
				unsigned int bpos = 0;
				struct dirent64 *d;
				char *buf = (char *) dirp;
				while (1) {
					d = (struct dirent64 *) (buf + bpos);
					if (count - bpos < offsetof(struct dirent64, d_name))
						break;
					if (bpos + d->d_reclen > count)
						break;
					bpos += d->d_reclen;
				}
				if (bpos < count) {
					fseeko(vufs_fdprivate->getdentsf, - (int) (count - bpos), SEEK_CUR);
					retval -= count - bpos;
				}
				/* the buffer is so short that it does not fit one
					 entry. Return EINVAL! */
				if (retval == 0) {
					errno = EINVAL;
					retval = -1;
				}
			}
		}
		pthread_mutex_unlock(&(vufs->mutex));
		//printk("vu_vufs_getdents64 %d\n", retval);
		return retval;
	} else {
		errno = EBADF;
		return -1;
	}
	//return syscall(__NR_getdents64, fd, dirp, count);
}

static int vufs_confirm(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vufs_t *vufs = vuht_get_private_data(ht);
	char *path = arg;
	char *shortpath = path + vuht_get_objlen(ht);
	char **exception;

	for (exception = vufs->except; *exception; exception++) {
		int len = strlen(*exception);
		if (strncmp(shortpath,*exception,len) == 0 &&
				(shortpath[len] == '/' || shortpath[len]=='\0'))
			return 0;
	}
	return 1;
}

static int set_mount_options(const char *input, struct vufs_t *vufs) {
  int tagc = stropt(input, NULL, NULL, 0);
	int retval = 0;
  if(tagc > 1) {
    char buf[strlen(input)+1];
    char *tags[tagc];
    char *args[tagc];
		int excl_choice = 0;
    stropt(input, tags, args, buf);
    for (int i=0; tags[i] != NULL; i++) {
			uint64_t strcasetag = strcase(tags[i]);
			if (vufs == NULL) {
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						retval++;
						if (args[i] == NULL) {
							printk(KERN_ERR "vufs: %s requires an arg\n", tags[i]);
							return -1;
						}
						break;
					case STRCASE(m,o,v,e):
					case STRCASE(m,e,r,g,e):
					case STRCASE(c,o,w):
					case STRCASE(m,i,n,c,o,w):
						if (args[i] != NULL) {
							printk(KERN_ERR "vufs: %s need no args\n", tags[i]);
							return -1;
						}
						if (++excl_choice > 1) {
							printk(KERN_ERR "vufs: move, merge, cow and mincow are mutually exclusive\n", tags[i]);
              return -1;
            }
						break;
					default:
						printk(KERN_ERR "vufs: %s unknown tag\n", tags[i]);
						return -1;
						break;
				}
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						retval++;
						break;
				}
			} else {
				switch(strcasetag) {
					case STRCASE(e,x,c,e,p,t):
						vufs->except[retval++] = strdup(args[i]);
						vufs->except[retval] = NULL;
						break;
					case STRCASE(m,o,v,e):
						break;
					case STRCASE(m,e,r,g,e):
						vufs->flags |= VUFS_MERGE;
						break;
					case STRCASE(c,o,w):
						vufs->flags |= VUFS_MERGE | VUFS_COW;
						break;
					case STRCASE(m,i,n,c,o,w):
						vufs->flags |= VUFS_MERGE | VUFS_COW | VUFS_MINCOW;
						break;
				}
			}
		}
	}
	return retval;
}

int vu_vufs_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	struct vufs_t *new_vufs;
	int nexcept;
	if (data == NULL)
		data = "";
	if ((nexcept = set_mount_options(data, NULL)) < 0) {
		errno = EINVAL;
		return -1;
	}

	new_vufs = malloc(sizeof(struct vufs_t) + sizeof(char *) * (nexcept + 1));
	if (new_vufs == NULL) {
		errno = ENOMEM;
		goto mallocerr;
	}
	new_vufs->source = strdup(source);
	new_vufs->target = strdup(target);
	new_vufs->except[0] = 0;
	new_vufs->rdirfd = -1;
	new_vufs->vdirfd = -1;
	new_vufs->ddirfd = -1;
	new_vufs->flags = 0;
	set_mount_options(data, new_vufs);
	if (mountflags & MS_RDONLY) {
		new_vufs->flags |= VUFS_RDONLY;
		/* if it is RDONLY then COW or MINCOW become MERGE */
		if (new_vufs->flags & VUFS_MERGE)
			new_vufs->flags &= ~(VUFS_COW | VUFS_MINCOW);
	}
	new_vufs->vdirfd = open(source, O_PATH);
	if (new_vufs->vdirfd < 0) {
		errno = ENOENT;
		goto vdirerr;
	}
	if (new_vufs->flags & VUFS_MERGE) {
		new_vufs->rdirfd = open(target, O_PATH);
		if (new_vufs->rdirfd < 0) {
			errno = ENOENT;
			goto rdirerr;
		}
		if ((new_vufs->flags & VUFS_RDONLY) == 0) {
			mkdirat(new_vufs->vdirfd, ".-", 0777);
			new_vufs->ddirfd = openat(new_vufs->vdirfd, ".-", O_PATH, 0777);
		}
	}
	pthread_mutex_init(&(new_vufs->mutex), NULL);
	pthread_mutex_lock(&(new_vufs->mutex));

  vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, vufs_confirm, new_vufs);

	pthread_mutex_unlock(&(new_vufs->mutex));
  errno = 0;
  return 0;
rdirerr:
	close(new_vufs->vdirfd);
vdirerr:
	free(new_vufs);
mallocerr:
	return -1;
}

int vu_vufs_umount2(const char *target, int flags) {
  struct vuht_entry_t *ht = vu_mod_getht();
  int ret_value;
  if ((ret_value = vuht_del(ht, flags)) < 0) {
    errno = -ret_value;
    return -1;
  }
  return 0;
}

void vu_vufs_cleanup(uint8_t type, void *arg, int arglen,struct vuht_entry_t *ht) {
  if (type == CHECKPATH) {
    struct vufs_t *vufs = vuht_get_private_data(ht);
    if (vufs == NULL) {
      errno = EINVAL;
    } else {
			if (vufs->ddirfd >= 0)
				close(vufs->ddirfd);
			if (vufs->rdirfd >= 0)
				close(vufs->rdirfd);
			close(vufs->vdirfd);
			pthread_mutex_destroy(&(vufs->mutex));
			free(vufs->source);
			free(vufs->target);
			free(vufs);
		}
  }
}

void *vu_vufs_init(void) {
  struct vu_service_t *s = vu_mod_getservice();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
  vu_syscall_handler(s, read) = read;
  vu_syscall_handler(s, write) = write;
  vu_syscall_handler(s, lseek) = lseek;
	vu_syscall_handler(s, pread64) = pread;
  vu_syscall_handler(s, pwrite64) = pwrite;
  vu_syscall_handler(s, fcntl) = fcntl;
#pragma GCC diagnostic pop
  return NULL;
}

int vu_vufs_fini(void *private) {
  return 0;
}

  struct vu_module_t vu_module = {
    .name = "vufs",
    .description = "vu filesystem patchworking"
  };

__attribute__((constructor))
  static void init(void) {
    debug_set_name(V, "VUFS");
  }

__attribute__((destructor))
  static void fini(void) {
    debug_set_name(V, "");
  }
