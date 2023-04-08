/* r_xxx compat defs for arch unsupported syscalls */

#ifndef R_TABLE_H
#error "do no include r_table_compat.h, use r_table.h instead"
#endif

#if !defined(r_fork) && defined(__NR_clone)
#  define r_fork() native_syscall(__NR_clone, SIGCHLD, NULL)
#endif

#if !defined(r_open) && defined(__NR_openat)
#  define  r_open(...) native_syscall(__NR_openat, AT_FDCWD, ## __VA_ARGS__)
#endif

#if !defined(r_lstat)
#  if defined(__NR_fstatat)
#     define r_lstat(path, buf) native_syscall(__NR_fstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW)
#  elif defined(__NR3264_fstatat)
#     define r_lstat(path, buf) native_syscall(__NR3264_fstatat, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW)
#  endif
#endif

#if !defined(r_readlink) && defined(__NR_readlinkat)
#  define r_readlink(...) native_syscall(__NR_readlinkat, AT_FDCWD, ## __VA_ARGS__)
#endif

#if !defined(r_unlink) && defined(__NR_unlinkat)
#  define r_unlink(pathname) native_syscall(__NR_unlinkat, AT_FDCWD, pathname, 0)
#endif

#if !defined(r_rmdir) && defined(__NR_unlinkat)
#  define r_rmdir(pathname) native_syscall(__NR_unlinkat, AT_FDCWD, pathname, AT_REMOVEDIR)
#endif

#if !defined(r_dup2) && defined(__NR_dup3)
#   define r_dup2(oldfd, newfd)  (oldfd == newfd) ? newfd : native_syscall(__NR_dup3, oldfd, newfd, 0)
#endif

#if !defined(r_poll) && defined(__NR_ppoll)
#   define r_poll(fds, nfds, timeout) \
	native_syscall(__NR_ppoll, fds, nfds, &(struct timespec){.tv_sec = timeout}, NULL)
#endif

#if !defined(r_epoll_wait) && defined(__NR_epoll_pwait)
#   define r_epoll_wait(epfd, events, maxevents, timeout) \
	native_syscall(__NR_epoll_pwait, epfd, events, maxevents, timeout, NULL)
#endif
