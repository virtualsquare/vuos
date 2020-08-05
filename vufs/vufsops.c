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
#include <sys/sysmacros.h>
#include <sys/fsuid.h>
#include <pthread.h>
#include <vufstat.h>
#include <vufs.h>
#include <vufs_path.h>
#include <vufs_getdents.h>
#include <vufsa.h>
#include <stdarg.h>
#include <sys/file.h>

#define MAXSIZE ((1ULL<<((sizeof(size_t)*8)-1))-1)
#define CHUNKSIZE 4096

static void vufs_copyfile_stat(struct vufs_t *vufs, const char *path,
		struct vu_stat *rstat, struct vu_stat *vstat) {
	uid_t newuid = -1;
	gid_t newgid = -1;
	if (((rstat->st_mode ^ vstat->st_mode) & ~S_IFMT) != 0) {
		if (fchmodat(vufs->vdirfd, path, rstat->st_mode & ~S_IFMT, AT_SYMLINK_NOFOLLOW) < 0) {
			if (((rstat->st_mode ^ vstat->st_mode) & 0777) != 0)
				fchmodat(vufs->vdirfd, path, rstat->st_mode & 0777, AT_SYMLINK_NOFOLLOW);
		}
	}
	if (rstat->st_uid != vstat->st_uid)
		newuid = rstat->st_uid;
	if (rstat->st_gid != vstat->st_gid)
		newgid = rstat->st_gid;
	if (newuid != (uid_t) -1 || newgid != (gid_t) -1)
		fchownat(vufs->vdirfd, path, newuid, newgid, AT_SYMLINK_NOFOLLOW);
}

static void vufs_copyfile_vufstat(struct vufs_t *vufs, const char *path,
		struct vu_stat *rstat, struct vu_stat *vstat) {
	uint32_t mask = vufstat_cmpstat(rstat, vstat) & VUFSTAT_COPYMASK;
	vufstat_write(vufs->ddirfd, path, rstat, mask);
}

static void vufs_newfilestat(struct vufs_t *vufs, const char *path, int fd, mode_t mode) {
	struct vu_stat vstat;
	struct vu_stat newvstat;
	uint32_t mask;
	newvstat.st_uid = setfsuid(-1);
	newvstat.st_gid = setfsgid(-1); // XXX TBD setgid bid on dir
	newvstat.st_mode = mode & ~vu_mod_getumask();
	fchown(fd, newvstat.st_uid, newvstat.st_gid);
	if (fchmod(fd, newvstat.st_mode & ~S_IFMT) < 0)
		fchmod(fd, newvstat.st_mode & 0777);
	fstat(fd, &vstat);
	mask = vufstat_cmpstat(&vstat, &newvstat) & VUFSTAT_COPYMASK;
	vufstat_write(vufs->ddirfd, path, &newvstat, mask);
}

static void vufs_copyfile_create_path_cb(void *arg, int dirfd, const char *path) {
	struct vufs_t *vufs = arg;
	struct vu_stat rstat;
	struct vu_stat vstat;
	struct vu_stat newvstat;
	if (fstatat(vufs->vdirfd, path, &vstat, AT_EMPTY_PATH) == 0 &&
			fstatat(vufs->rdirfd, path, &rstat, AT_EMPTY_PATH) == 0) {
		vufstat_merge(vufs->ddirfd, path, &rstat);
		vufs_copyfile_stat(vufs, path, &rstat, &vstat);
		if (fstatat(vufs->vdirfd, path, &newvstat, AT_EMPTY_PATH) == 0) {
			uint32_t mask = vufstat_cmpstat(&rstat, &newvstat) & VUFSTAT_COPYMASK;
			vufstat_write(vufs->ddirfd, path, &rstat, mask);
		}
	}
}

static int vufs_copyfile(struct vufs_t *vufs, const char *path, size_t truncate) {
	int fdin = openat(vufs->rdirfd, path, O_RDONLY, 0);
	if (fdin >= 0) {
		struct vu_stat instat;
		fstat(fdin, &instat);
		if (!S_ISREG(instat.st_mode)) {
			errno = -EIO;
			close(fdin);
			return -1;
		} else {
			int fdout;
			vufs_create_path(vufs->vdirfd, path, vufs_copyfile_create_path_cb, vufs);
			fdout = openat(vufs->vdirfd, path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (fdout >= 0) {
				struct vu_stat outstat;
				size_t nread, readsize = CHUNKSIZE;
				char buf[CHUNKSIZE];
				fstat(fdout, &outstat);
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
				vufstat_merge(vufs->ddirfd, path, &instat);
				vufs_copyfile_stat(vufs, path, &instat, &outstat);
				fstat(fdout, &outstat);
				vufs_copyfile_vufstat(vufs, path, &instat, &outstat);
				close(fdin);
				close(fdout);
				return nread == 0 ? 0 : -1;
			} else {
				close(fdout);
				errno = EIO;
				return -1;
			}
		}
	}	else {
		close(fdin);
		return -1;
	}
}

/* RDONLY SYSCALLS */
int vu_vufs_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	if (sfd >= 0) {
		return fstat(sfd, buf);
	} else {
		struct vufs_t *vufs = vu_get_ht_private_data();
		int retval = 0;
		vufsa_status status = VUFSA_START;
		pathname += 1;
		vufsa_next vufsa_next = vufsa_select(vufs, O_RDONLY);
		while ((status = vufsa_next(status, vufs, pathname, retval)) != VUFSA_EXIT) {
			//printk("LSTAT status %d %d %d\n", status,retval, errno);
			switch (status) {
				case VUFSA_DOREAL:
					retval = fstatat(vufs->rdirfd, pathname, buf, flags | AT_EMPTY_PATH);
					break;
				case VUFSA_DOVIRT:
					retval = fstatat(vufs->vdirfd, pathname, buf, flags | AT_EMPTY_PATH);
					break;
				case VUFSA_FINAL:
					if (retval == 0)
						vufstat_merge(vufs->ddirfd, pathname, buf);
					break;
				case VUFSA_ERR:
					retval = -1;
					break;
			}
		}
		printkdebug(V, "LSTAT path:%s retvalue:%d errno:%d", pathname, retval, retval < 0 ? errno : 0);
		return retval;
	}
}

int vu_vufs_access(char *path, int mode, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
	int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_RDONLY);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
        retval = faccessat(vufs->rdirfd,
						*path ? path : vufs->target,
						mode, flags);
        break;
      case VUFSA_DOVIRT:
        retval = faccessat(vufs->vdirfd,
						*path ? path : vufs->target,
						mode, flags);
        break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
	printkdebug(V, "ACCESS path:%s mode:%o retvalue:%d", path, mode, retval);
  return retval;
}

ssize_t vu_vufs_readlink(char *path, char *buf, size_t bufsiz) {
	struct vufs_t *vufs = vu_get_ht_private_data();
  vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_RDONLY);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
				retval = readlinkat(vufs->rdirfd, path, buf, bufsiz);
				break;
			case VUFSA_DOVIRT:
				retval = readlinkat(vufs->vdirfd, path, buf, bufsiz);
				break;
			case VUFSA_ERR:
				retval = -1;
        break;
    }
  }
	printkdebug(V, "READLINK path:%s retvalue:%d", path, retval);
	return retval;
}

int vu_vufs_statfs (const char *path, struct statfs *buf, int sfd, void *fdprivate) {
	if (sfd >= 0) {
		return fstatfs(sfd, buf);
	} else {
		struct vufs_t *vufs = vu_get_ht_private_data();
		vufsa_status status = VUFSA_START;
		int retval;
		path += 1;
		vufsa_next vufsa_next = vufsa_select(vufs, O_RDONLY);
		while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
			switch (status) {
				case VUFSA_DOREAL:
					sfd = openat(vufs->rdirfd, path, O_PATH | AT_EMPTY_PATH);
					if (sfd < 0)
						retval = -1;
					else {
						retval = fstatfs(sfd, buf);
						close(sfd);
					}
					break;
				case VUFSA_DOVIRT:
					sfd = openat(vufs->vdirfd, path, O_PATH | AT_EMPTY_PATH);
					if (sfd < 0)
						retval = -1;
					else {
						retval = fstatfs(sfd, buf);
						close(sfd);
					}
					break;
				case VUFSA_ERR:
					retval = -1;
					break;
			}
		}
		printkdebug(V, "STATFS path:%s retvalue:%d", path, retval);
		return retval;
	}
}

/* ALWAYS DELETE SYSCALLS */
int vu_vufs_unlink (const char *path) {
	struct vufs_t *vufs = vu_get_ht_private_data();
  vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_UNLINK);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
        retval = unlinkat(vufs->rdirfd, path, 0);
        break;
      case VUFSA_DOVIRT:
        retval = unlinkat(vufs->vdirfd, path, 0);
        break;
      case VUFSA_VUNLINK:
				retval = vufs_whiteout(vufs->ddirfd, path);
				break;
      case VUFSA_FINAL:
				if (vufs->ddirfd >= 0)
					vufstat_unlink(vufs->ddirfd, path);
				break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
  printkdebug(V, "UNLINK path:%s retvalue:%d", path, retval);
  return retval;
}

int vu_vufs_rmdir(const char *path) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	 vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
	if (vufs_enotempty_ck(vufs, path) < 0)
		retval = -1;
	else {
		vufsa_next vufsa_next = vufsa_select(vufs, O_UNLINK);
		while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
			switch (status) {
				case VUFSA_DOREAL:
					retval = unlinkat(vufs->rdirfd, path, AT_REMOVEDIR);
					break;
				case VUFSA_DOVIRT:
					retval = unlinkat(vufs->vdirfd, path, AT_REMOVEDIR);
					break;
				case VUFSA_VUNLINK:
					retval = vufs_whiteout(vufs->ddirfd, path);
					break;
				case VUFSA_FINAL:
					if (vufs->ddirfd >= 0)
						vufstat_unlink(vufs->ddirfd, path);
					break;
				case VUFSA_ERR:
					retval = -1;
					break;
			}
		}
	}
	printkdebug(V, "RMDIR path:%s retvalue:%d", path, retval);
	return retval;
}

/* ALWAYS CREATE SYSCALLS */
int vu_vufs_mkdir (const char *path, mode_t mode) {
	struct vufs_t *vufs = vu_get_ht_private_data();
  vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_CREAT | O_EXCL);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
				retval = mkdirat(vufs->rdirfd, path, mode);
        break;
      case VUFSA_DOVIRT:
				retval = mkdirat(vufs->vdirfd, path, mode);
        break;
			case VUFSA_FINAL:
				// now virt file exists, no need for whiteout file
				if (retval >=0)
					vufs_dewhiteout(vufs->ddirfd, path);
				break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
  printkdebug(V, "MKDIR path:%s mode:%o retvalue:%d", path, mode, retval);
  return retval;
}

int vu_vufs_symlink (const char *target, const char *path) {
	struct vufs_t *vufs = vu_get_ht_private_data();
  vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_CREAT | O_EXCL);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
        retval = symlinkat(target, vufs->rdirfd, path);
        break;
      case VUFSA_DOVIRT:
        retval = symlinkat(target, vufs->vdirfd, path);
        break;
			case VUFSA_FINAL:
				// now virt file exists, no need for whiteout file
				if (retval >=0)
					vufs_dewhiteout(vufs->ddirfd, path);
				break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
  printkdebug(V, "SYMLINK path:%s target:%s retvalue:%d", path, target, retval);
  return retval;
}

int vu_vufs_mknod (const char *path, mode_t mode, dev_t dev) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
  int retval;
  path += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_CREAT | O_EXCL);
  while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
        retval = mknodat(vufs->rdirfd, path, mode, dev);
        break;
      case VUFSA_DOVIRT:
        retval = mknodat(vufs->vdirfd, path, mode, dev);
				if (retval < 0 && vufs->ddirfd >= 0) {
					struct vu_stat buf;
					retval = mknodat(vufs->vdirfd, path,
							(mode & ~S_IFMT) | S_IFREG, 0);
					buf.st_mode = mode;
					buf.st_rdev = dev;
					vufstat_write(vufs->ddirfd, path, &buf, VUFSTAT_TYPE | VUFSTAT_RDEV);
				}
        break;
      case VUFSA_FINAL:
        // now virt file exists, no need for whiteout file
        if (retval >=0)
          vufs_dewhiteout(vufs->ddirfd, path);
        break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
  printkdebug(V, "MKNOD path:%s mode:%o major:%d minor:%d retval:%d",
			path, mode, major(dev), minor(dev), retval);
  return retval;
}

/* LINK - RENAME */
int vu_vufs_link (const char *oldpath, const char *newpath) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
	int retval;
	newpath += 1;
	oldpath += 1;
	vufsa_next vufsa_next = vufsa_select(vufs, O_CREAT | O_EXCL);
	while ((status = vufsa_next(status, vufs, newpath, retval)) != VUFSA_EXIT) {
		switch (status) {
			case VUFSA_DOREAL:
				retval = linkat(vufs->rdirfd, oldpath, vufs->rdirfd, newpath, 0);
				break;
			case VUFSA_DOVIRT:
				retval = linkat(vufs->vdirfd, oldpath, vufs->vdirfd, newpath, 0);
				if (vufs->rdirfd >= 0) {
					if (retval < 0 && errno == ENOENT) {
						retval = vufs_copyfile(vufs, oldpath, MAXSIZE);
						if (retval == 0) {
							retval = linkat(vufs->vdirfd, oldpath, vufs->vdirfd, newpath, 0);
							if (retval < 0) {
                unlinkat(vufs->vdirfd, oldpath, 0);
                vufstat_unlink(vufs->ddirfd, oldpath);
              }
						}
						if (retval == 0)
							vufstat_link(vufs->ddirfd, oldpath, newpath);
					}
				}
				break;
			case VUFSA_FINAL:
				// now virt file exists, no need for whiteout file
				if (retval >=0)
					vufs_dewhiteout(vufs->ddirfd, newpath);
				break;
			case VUFSA_ERR:
				retval = -1;
				break;
		}
	}
	printkdebug(V, "LINK oldpath:%s newpath:%s retvalue:%d", oldpath, newpath, retval);
	return retval;
}

int vu_vufs_rename (const char *oldpath, const char *newpath, int flags) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	  vufsa_status status = VUFSA_START;
  int retval;
  newpath += 1;
  oldpath += 1;
  vufsa_next vufsa_next = vufsa_select(vufs, O_RDWR);
  while ((status = vufsa_next(status, vufs, newpath, retval)) != VUFSA_EXIT) {
    switch (status) {
      case VUFSA_DOREAL:
        retval = syscall(__NR_renameat2, vufs->rdirfd, oldpath, vufs->rdirfd, newpath, flags);
        break;
      case VUFSA_DOVIRT:
        retval = syscall(__NR_renameat2, vufs->vdirfd, oldpath, vufs->vdirfd, newpath, flags);
				if (vufs->rdirfd >= 0) {
					if (retval < 0 && errno == ENOENT && vufs->rdirfd >= 0) {
						retval = vufs_copyfile(vufs, oldpath, MAXSIZE);
						if (retval == 0) {
							retval = syscall(__NR_renameat2, vufs->vdirfd, oldpath, vufs->vdirfd, newpath, flags);
							if (retval < 0) {
								unlinkat(vufs->vdirfd, oldpath, 0);
								vufstat_unlink(vufs->ddirfd, oldpath);
							} else {
								int rv = vufs_whiteout(vufs->ddirfd, oldpath);
								printk("vufs_whiteout ret %d\n", rv);
							}
						}
					}
					if (retval >= 0)
						vufstat_rename(vufs->ddirfd, oldpath, newpath, flags);
				}
				break;
			case VUFSA_FINAL:
				// now virt file exists, no need for whiteout file
				if (retval >=0)
					vufs_dewhiteout(vufs->ddirfd, newpath);
				break;
      case VUFSA_ERR:
        retval = -1;
        break;
    }
  }
  printkdebug(V, "RENAME oldpath:%s newpath:%s retvalue:%d", oldpath, newpath, retval);
  return retval;
	//return syscall(__NR_renameat2, vufs->vdirfd, newpath + 1, vufs->vdirfd, oldpath + 1, flags);
}

/* TRUNCATE always modifies never creates */

/* for an unknown reason truncateat is missing */
static int fake_truncateat(const char *dir, const char *path, off_t length) {
	int pathlen = strlen(dir) + strlen(path) + 2;
	char pathname[pathlen];
	snprintf(pathname, pathlen, "%s/%s", dir, path);
	return truncate(pathname, length);
}

int vu_vufs_truncate(const char *path, off_t length, int sfd, void *fdprivate) {
	if (sfd >= 0) {
    return ftruncate(sfd, length);
  } else {
		struct vufs_t *vufs = vu_get_ht_private_data();
		vufsa_status status = VUFSA_START;
		int retval;
		path += 1;
		vufsa_next vufsa_next = vufsa_select(vufs, O_RDWR);
		while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
			switch (status) {
				case VUFSA_DOREAL:
					retval = fake_truncateat(vufs->source, path, length);
					break;
				case VUFSA_DOVIRT:
					retval = fake_truncateat(vufs->target, path, length);
					break;
				case VUFSA_DOCOPY:
					retval = vufs_copyfile(vufs, path, length);
					// now virt file exists, no need for whiteout file
					// maybe useless?
					if (retval >=0)
						vufs_dewhiteout(vufs->ddirfd, path);
					break;
				case VUFSA_ERR:
					retval = -1;
					break;
			}
		}
		printkdebug(V, "TRUNCATE path:%s len:%zd retvalue:%d", path, length, retval);
		return retval;
	}
}

int vu_vufs_utimensat (int dirfd, const char *path,
    const struct timespec times[2], int flags, int sfd, void *fdprivate) {
	if (sfd >= 0) {
		return futimens(sfd, times);
	} else {
		    struct vufs_t *vufs = vu_get_ht_private_data();
    vufsa_status status = VUFSA_START;
    int retval;
    path += 1;
    vufsa_next vufsa_next = vufsa_select(vufs, O_RDWR);
    while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
      switch (status) {
        case VUFSA_DOREAL:
          retval = utimensat(vufs->rdirfd,
							*path ? path : vufs->source,
							times, flags | AT_SYMLINK_NOFOLLOW);
          break;
        case VUFSA_DOVIRT:
          retval = utimensat(vufs->vdirfd,
							*path ? path : vufs->target,
							times, flags | AT_SYMLINK_NOFOLLOW);
          break;
        case VUFSA_DOCOPY:
          retval = vufs_copyfile(vufs, path, MAXSIZE);
          // now virt file exists, no need for whiteout file
          // maybe useless?
          if (retval >=0)
            vufs_dewhiteout(vufs->ddirfd, path);
          break;
        case VUFSA_ERR:
          retval = -1;
          break;
      }
    }
    printkdebug(V, "UTIMENSAT path:%s retvalue:%d", path, retval);
    return retval;
  }
}

/* MODIFY STAT SYSCALLS */
int vu_vufs_lchown(const char *path, uid_t owner, gid_t group, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
	int retval;
	path += 1;
	vufsa_next vufsa_next = vufsa_select(vufs, O_RDWR);
	while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
		switch (status) {
			case VUFSA_DOREAL:
				retval = fchownat(vufs->rdirfd, path, owner, group, AT_EMPTY_PATH);
				break;
			case VUFSA_DOVIRT:
				retval = fchownat(vufs->vdirfd, path, owner, group, AT_EMPTY_PATH);
				if (vufs->vdirfd >= 0) {
					struct vu_stat statbuf = {.st_uid = owner, .st_gid = group};
					uint32_t mask = 0;
					if (owner != (uid_t) -1) mask |= VUFSTAT_UID;
					if (group != (gid_t) -1) mask |= VUFSTAT_GID;
					vufstat_update(vufs->ddirfd, path, &statbuf, mask,
							retval < 0 && (errno == EPERM || errno == ENOENT) ? O_CREAT : 0);
					retval = 0;
				}
				break;
			case VUFSA_DOCOPY:
				// copy on chown?
				// retval = vufs_copyfile(vufs, pathname, flags & O_TRUNC ? 0 : MAXSIZE);
				break;
			case VUFSA_ERR:
				retval = -1;
				break;
		}
	}
	printkdebug(V, "CHOWN path:%s uid:%d gid:%d retvalue:%d", path, owner, group, retval);
	return retval;
}

int vu_vufs_chmod(const char *path, mode_t mode, int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
	int retval;
	path += 1;
	vufsa_next vufsa_next = vufsa_select(vufs, O_RDWR);
	while ((status = vufsa_next(status, vufs, path, retval)) != VUFSA_EXIT) {
		switch (status) {
			case VUFSA_DOREAL:
				retval = fchmodat(vufs->rdirfd, path, mode, AT_EMPTY_PATH);
				break;
			case VUFSA_DOVIRT:
				retval = fchmodat(vufs->vdirfd, path, mode, AT_EMPTY_PATH);
				if (vufs->vdirfd >= 0) {
          struct vu_stat statbuf = {.st_mode = mode};
					vufstat_update(vufs->ddirfd, path, &statbuf, VUFSTAT_MODE,
							retval < 0 && (errno == EPERM || errno == ENOENT) ? O_CREAT : 0);
          retval = 0;
        }
				break;
			case VUFSA_DOCOPY:
				// copy on chmod?
				// retval = vufs_copyfile(vufs, pathname, flags & O_TRUNC ? 0 : MAXSIZE);
				break;
			case VUFSA_ERR:
				retval = -1;
				break;
		}
	}
	printkdebug(V, "CHMOD path:%s uid:0%o retvalue:%d", path, mode, retval);
	return retval;
}

/* OPEN (can be RDONLY, RDWR CREATE!) */
int vu_vufs_open(const char *pathname, int flags, mode_t mode, void **private) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	vufsa_status status = VUFSA_START;
	int retval;
	const char *filepath;
	mode_t oldmode = vu_mod_getmode();
	pathname += 1;
	if (flags == O_UNLINK) flags = O_PATH; //PATH+EXCL has the special meaning of UNLINK
	vufsa_next vufsa_next = vufsa_select(vufs, flags);
	while ((status = vufsa_next(status, vufs, pathname, retval)) != VUFSA_EXIT) {
		switch (status) {
			case VUFSA_DOREAL:
				filepath = *pathname ? pathname : vufs->target;
				retval = openat(vufs->rdirfd, filepath, flags, mode);
				break;
			case VUFSA_DOVIRT:
				filepath = *pathname ? pathname : vufs->source;
				if (oldmode == 0)
					vufs_create_path(vufs->vdirfd, filepath, vufs_copyfile_create_path_cb, vufs);
				retval = openat(vufs->vdirfd, filepath, flags, mode);
				break;
			case VUFSA_DOCOPY:
				retval = vufs_copyfile(vufs, pathname, flags & O_TRUNC ? 0 : MAXSIZE);
				break;
			case VUFSA_FINAL:
				// open created this file
				if (retval >=0 && (flags & O_CREAT) && oldmode == 0) {
					// no need for whiteout file
					vufs_dewhiteout(vufs->ddirfd, pathname);
					vufs_newfilestat(vufs, pathname, retval, mode);
				}
				// fdprivate for getdents
				if (retval >= 0 && S_ISDIR(oldmode)) {
					int pathlen = strlen(pathname) + 1;
					struct vufs_fdprivate *vufs_fdprivate =
						malloc(sizeof(struct vufs_fdprivate) + pathlen);
					vufs_fdprivate->getdentsf = NULL;
					strncpy(vufs_fdprivate->path, pathname, pathlen);
					*private = vufs_fdprivate;
				} else
					*private = NULL;
				break;
			case VUFSA_ERR:
				retval = -1;
				break;
		}
	}
	printkdebug(V, "OPEN path:%s flags:%o mode:%o retvalue:%d", pathname, flags, mode, retval);
	return retval;
}

int vu_vufs_close(int fd, void *fdprivate) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;
	pthread_mutex_lock(&(vufs->mutex));
	if (open_fds[fd] != -1) {
		// TODO: check correctness
		close(open_fds[fd]);
		open_fds[fd] = -1;
	}
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

// RECORD LOCKING SYSCALLS
int vu_vufs_fcntl(int fd, int cmd, ...) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;

	va_list ap;
	va_start(ap, cmd);

	switch (cmd) {
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case F_OFD_SETLK:
		case F_OFD_SETLKW:
		case F_OFD_GETLK: ;
						  /* retrieve variadic parameters */
						  struct flock *lockinfo = va_arg(ap, struct flock*);
						  char *dest_path = va_arg(ap, char *);
						  vufsa_status status = VUFSA_START;
						  // if this is used, vu_fd_table.h must be included
						  // int flags = vu_fd_get_fdflags(fd, 0);
						  int flags = O_RDWR;
						  int vfd = fd;
						  dest_path += 1;

						  vufsa_next vufsa_next = vufsa_select(vufs, flags);
						  while ((status = vufsa_next(status, vufs, dest_path, retval)) != VUFSA_EXIT) {
							  switch (status) {
								  case VUFSA_DOREAL:
									  retval = fcntl(fd, cmd, lockinfo);
									  break;
								  case VUFSA_DOVIRT:
									  if (open_fds[fd] != -1) {
										  vfd = open_fds[fd];
									  } else {
										  // TODO: check that this fd is effectively closed
										  vfd = openat(vufs->vdirfd, dest_path, flags);
										  open_fds[fd] = vfd;
									  }
									  retval = fcntl(vfd, cmd, lockinfo);
									  break;
								  case VUFSA_DOCOPY:
									  vufs_copyfile(vufs, dest_path, MAXSIZE);
									  break;
								  case VUFSA_ERR:
									  retval = -1;
								  case VUFSA_FINAL:
									  break;
							  }
						  }
						  break;

		case F_GETOWN_EX:
		case F_SETOWN_EX:
						  retval = fcntl(fd, cmd, va_arg(ap, struct f_owner_ex*));
						  break;

		case F_GET_RW_HINT:
		case F_SET_RW_HINT:
		case F_GET_FILE_RW_HINT:
		case F_SET_FILE_RW_HINT:
						  retval = fcntl(fd, cmd, va_arg(ap, uint64_t *));
						  break;

		default:
						  retval = fcntl(fd, cmd, va_arg(ap, int));
						  break;
	}

	va_end(ap);
	return retval;
}

int vu_vufs_flock(int fd, int operation, char *dest_path) {
	struct vufs_t *vufs = vu_get_ht_private_data();
	int retval;

	dest_path++;
	retval = vufs_copyfile(vufs, dest_path, MAXSIZE);

	if (retval < 0) {
		printkdebug(V, "Could not create virtual copy of file %s", dest_path);
		errno = EBADF;
		retval = -1;
	} else {
		int flags = O_RDWR;

		// if this is used, vu_fd_table.h must be included
		// int flags = vu_fd_get_fdflags(fd, 0);

		// TODO: remember to close this fd when the original one is
		int vfd = openat(vufs->vdirfd, dest_path, flags);

		if (vfd < 0) {
			printkdebug(V, "Could not open virtual copy of %s", dest_path);
			errno = EBADF;
			retval = -1;
		} else {
			retval = flock(vfd, operation);
			printkdebug(V, "fcntl returned %d", retval);
		}
	}

	return retval;
}

