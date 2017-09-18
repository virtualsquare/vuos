#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <utime.h>
#include <sys/syscall.h>

#include <vu_log.h>
#include <xcommon.h>
#include <umvu_peekpoke.h>
#include <hashtable.h>
#include <arch_table.h>
#include <vu_fd_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
#include <path_utils.h>
#include <vu_wrapper_utils.h>

/* lstat stat fstat fstatat/newfstatat */
void wi_lstat(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		syscall_arg_t bufaddr;
		int flags = 0;
		int sfd = -1;
		void *private = NULL;
		/* local bufs */
		struct vu_stat *statbuf;
		/* fetch args */
		switch (syscall_number) {
			case __NR_stat:
			case __NR_lstat:
				bufaddr = sd->syscall_args[1];
				break;
			case __NR_fstat:
				bufaddr = sd->syscall_args[1];
				sfd = sd->syscall_args[0];
				sfd = (vu_fd_get_sfd(sfd, &private, nested));
				break;
#ifdef __NR_fstatat
			case __NR_fstatat:
#endif
#ifdef __NR_newfstatat
			case __NR_newfstatat:
#endif
				bufaddr = sd->syscall_args[2];
				flags = sd->syscall_args[3];
		}
		vu_alloc_local_arg(bufaddr, statbuf, sizeof(*statbuf), nested);
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_lstat)(sd->extra->path, statbuf, flags, sfd, private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		vu_poke_arg(bufaddr, statbuf, sizeof(*statbuf), nested);
		sd->ret_value = ret_value;
	} 
}

/* readlink, readlinkat */
void wi_readlink(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
    int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		ssize_t ret_value;
		/* args */
		syscall_arg_t bufaddr;
		size_t bufsize;
		/* local bufs */
		char *buf;
		size_t len;
		/* fetch args */
		switch (syscall_number) {
			case __NR_readlink:
				bufaddr = sd->syscall_args[1];
				bufsize = sd->syscall_args[2];
				break;
			case __NR_readlinkat:
				bufaddr = sd->syscall_args[2];
				bufsize = sd->syscall_args[3];
				break;
		}
		vu_alloc_local_arg(bufaddr, buf, PATH_MAX + 1, nested);
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_readlink)(sd->extra->path, buf, PATH_MAX + 1);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		len = strlen(buf) + 1;
		if (len > bufsize) 
			len = bufsize;
		vu_poke_arg(bufaddr, buf, len, nested);
		sd->ret_value = ret_value;
	}
}

/* access, faccessat */
void wi_access(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int mode;
		int flags;
		/* local bufs */
		/* fetch args */
		switch (syscall_number) {
			case __NR_access:
				mode = sd->syscall_args[1];
				flags = 0;
				break;
			case __NR_faccessat:
				mode = sd->syscall_args[2];
				flags = sd->syscall_args[3];
				break;
		}
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_access)(sd->extra->path, mode, flags);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/* unlink, unlinkat */
void wi_unlink(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int flags;
		/* local bufs */
		/* fetch args */
		switch (syscall_number) {
			case __NR_unlink:
				flags = 0;
				break;
			case __NR_unlinkat:
				flags = sd->syscall_args[2];
				break;
		}
		/* call */
		sd->action = SKIP;
		if (flags & AT_REMOVEDIR)
			ret_value = service_syscall(ht, __VU_rmdir)(sd->extra->path);
		else
			ret_value = service_syscall(ht, __VU_unlink)(sd->extra->path);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/* mkdir */
void wi_mkdir(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		int mode;
		/* local bufs */
		/* fetch args */
		switch (syscall_number) {
			case __NR_mkdir:
				mode = sd->syscall_args[1];
				break;
			case __NR_mkdirat:
				mode = sd->syscall_args[2];
				break;
		}
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_mkdir)(sd->extra->path, mode);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/* rmdir */
void wi_rmdir(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int ret_value;
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_rmdir)(sd->extra->path);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/* lchown, fchown, chown, fchownat */
void wi_lchown(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		uid_t owner;
		gid_t group;
		int flags = 0;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_lchown:
			case __NR_chown:
				owner = sd->syscall_args[1];
				group = sd->syscall_args[2];
				break;
			case __NR_fchown:
				owner = sd->syscall_args[1];
				group = sd->syscall_args[2];
				sfd = sd->syscall_args[0];
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
			case __NR_fchownat:
				owner = sd->syscall_args[2];
				group = sd->syscall_args[3];
				flags = sd->syscall_args[4];;
				break;
		}
		/* call */
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_lchown)(sd->extra->path, owner, group, flags, sfd, private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/* chmod fchmod fchmodat */
void wi_chmod(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		/* standard args */
		int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		int ret_value;
		/* args */
		mode_t mode;
		int flags = 0;
		int sfd = -1;
		void *private = NULL;
		/* fetch args */
		switch (syscall_number) {
			case __NR_chmod:
				mode = sd->syscall_args[1];
				break;
			case __NR_fchmod:
				mode = sd->syscall_args[1];
				sfd = sd->syscall_args[0];
				sfd = vu_fd_get_sfd(sfd, &private, nested);
				break;
			case __NR_fchmodat:
				mode = sd->syscall_args[2];
				flags = sd->syscall_args[3];
				break;
		}
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_chmod)(sd->extra->path, mode, flags, sfd, private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

static void utime2utimen(struct utimbuf *in_times, struct timespec *out_times) {
  out_times[0].tv_sec = in_times->actime;
  out_times[1].tv_sec = in_times->modtime;
  out_times[0].tv_nsec = out_times[1].tv_nsec = 0;
}

static void utimes2utimen(struct timeval *in_times, struct timespec *out_times) {
  out_times[0].tv_sec = in_times[0].tv_sec;
  out_times[1].tv_sec = in_times[1].tv_sec;
  out_times[0].tv_nsec = in_times[0].tv_usec * 1000;
  out_times[1].tv_nsec = in_times[1].tv_usec * 1000;
}

/*  utimensat, utime, utimes, futimesat */
void wi_utimensat(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  if (ht) {
    /* standard args */
    int nested = sd->extra->nested;
    int syscall_number = sd->syscall_number;
    int ret_value;
    /* args */
		int inarg = 1;
		struct timespec times[2];
		int flags = 0;
		int sfd = -1;
    void *private = NULL;
    /* fetch args */
    switch (syscall_number) {
			case __NR_utime:
			case __NR_utimes:
				break;
			case __NR_futimesat:
				inarg = 2;
				break;
			case __NR_utimensat: {
														 uintptr_t pathaddr = sd->syscall_args[1];
														 if (pathaddr == (uintptr_t) NULL) {
															 vu_fd_get_sfd(sfd, &private, nested);
															 sfd = vu_fd_get_sfd(sfd, &private, nested);
														 }
														 inarg = 2;
														 flags = sd->syscall_args[3];
													 }
													 break;
		}
		if (sd->syscall_args[inarg] == (uintptr_t) NULL) {
			clock_gettime(CLOCK_REALTIME, &times[0]);
			times[1] = times[0];
    } else {
			if (nested) {
				switch (syscall_number) {
					case __NR_utime: {
														 struct utimbuf *in_times = (struct utimbuf *) sd->syscall_args[inarg];
														 utime2utimen(in_times, times);
													 }
													 break;
					case __NR_utimes:
					case __NR_futimesat: {
																 struct timeval *in_times = (struct timeval *) sd->syscall_args[inarg];
																 utimes2utimen(in_times, times);
															 }
															 break;
					case __NR_utimensat: {
																 struct timespec *in_times = (struct timespec *) sd->syscall_args[inarg];
																 times[0] = in_times[0];
																 times[1] = in_times[1];
															 }
															 break;
				}
			} else {
				uintptr_t addr = sd->syscall_args[inarg];
				switch (syscall_number) {
					case __NR_utime: {
														 struct utimbuf in_times;
														 umvu_peek_data(addr, &in_times, sizeof(in_times));
														 utime2utimen(&in_times, times);
													 }
													 break;
					case __NR_utimes:
					case __NR_futimesat: {
																 struct timeval in_times[2];
																 umvu_peek_data(addr, in_times, sizeof(in_times));
																 utimes2utimen(in_times, times);
															 }
															 break;
					case __NR_utimensat: umvu_peek_data(addr, times, sizeof(times));
															 break;

				}
			}
		}
		sd->action = SKIP;
		ret_value = service_syscall(ht,__VU_utimensat)(AT_FDCWD, sd->extra->path, times, flags, sfd, private);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/*  link, linkat */
void wi_link(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		int ret_value;
		char *oldpath;
		struct vuht_entry_t *htold;
		/* args */
		int dirfd;
		uintptr_t oldaddr;
		epoch_t e;
		switch (syscall_number) {
			case __NR_link: dirfd = AT_FDCWD;
											oldaddr = sd->syscall_args[0];
											break;
			case __NR_linkat: dirfd = sd->syscall_args[0];
												oldaddr = sd->syscall_args[1];
												break;
		}
		sd->action = SKIP;
		if (sd->extra->statbuf.st_mode != 0) {
			sd->ret_value = -EEXIST;
      return;
    }
		if (nested) 
			oldpath = get_nested_path(dirfd, (char *) oldaddr, NULL, 0);
		else
			oldpath = get_path(dirfd, oldaddr, NULL, 0);

		if (oldpath == NULL) {
			sd->ret_value = -errno;
			return;
		}
		e = set_vepoch(sd->extra->epoch);
		htold = vuht_pick(CHECKPATH, oldpath, NULL, 0);
		set_vepoch(e);
		if (ht != htold) {
			xfree(oldpath);
			sd->ret_value = -EXDEV;
			return;
		}
		ret_value = service_syscall(ht, __VU_link)(oldpath, sd->extra->path);
		xfree(oldpath);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/*  symlink, symlinkat */
void wi_symlink(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		int ret_value;
		char *target;
		printk("Link newpath %s\n", sd->extra->path);
		if (nested) 
			target = (char *) sd->syscall_args[0];
		else
			target = umvu_peekdup_path(sd->syscall_args[0]);
		sd->action = SKIP;
		ret_value = service_syscall(ht, __VU_symlink)(target, sd->extra->path);
		if (!nested)
			xfree(target);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}

/*  rename, renameat, renameat2 */
void wi_rename(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	if (ht) {
		int nested = sd->extra->nested;
		int syscall_number = sd->syscall_number;
		int ret_value;
		char *oldpath;
		struct vuht_entry_t *htold;
		/* args */
		int dirfd;
		uintptr_t oldaddr;
		int flags = 0;
		epoch_t e;
		switch (syscall_number) {
			case __NR_rename: dirfd = AT_FDCWD;
											oldaddr = sd->syscall_args[0];
											break;
			case __NR_renameat: dirfd = sd->syscall_args[0];
												oldaddr = sd->syscall_args[1];
												break;
			case __NR_renameat2: dirfd = sd->syscall_args[0];
													 oldaddr = sd->syscall_args[1];
													 flags = sd->syscall_args[4];
													 break;
		}
		sd->action = SKIP;
		if (nested)
			oldpath = get_nested_path(dirfd, (char *) oldaddr, NULL, 0);
		else
			oldpath = get_path(dirfd, oldaddr, NULL, 0);
		if (oldpath == NULL) {
			sd->ret_value = -errno;
			return;
		}
		e = set_vepoch(sd->extra->epoch);
		htold = vuht_pick(CHECKPATH, oldpath, NULL, 0);
		set_vepoch(e);
		if (ht != htold) {
			xfree(oldpath);
			sd->ret_value = -EXDEV;
			return;
		}
		ret_value = service_syscall(ht, __VU_rename)(oldpath, sd->extra->path, flags);
		if (ret_value < 0 && errno == ENOSYS) {
			/* workaround if rename is not available */
			ret_value = service_syscall(ht, __VU_link)(oldpath, sd->extra->path);
			if (ret_value == 0)
				ret_value = service_syscall(ht, __VU_unlink)(oldpath);
		}
		xfree(oldpath);
		if (ret_value < 0) {
			sd->ret_value = -errno;
			return;
		}
		/* store results */
		sd->ret_value = ret_value;
	}
}


