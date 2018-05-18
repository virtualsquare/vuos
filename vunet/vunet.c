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

#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <vumodule.h>

VU_PROTOTYPES(unreal)

	struct vu_module_t vu_module = {
		.name = "vunet",
		.description = "vu virtual networking"
	};

struct vunet_default_t {
  pthread_rwlock_t lock;
  size_t count;
	//struct vunet *defstack[AF_MAX];
};

static __thread struct vunet_default_t *vunet_default = NULL;

int vunet_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	errno = ENOSYS; return -1;
}

//int vunet_access(char *path, int mode, int flags) {
//	errno = ENOSYS; return -1;
//}

int vunet_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	errno = ENOSYS; return -1;
}

//int vunet_utimensat(int dirfd, const char *pathname,
//	errno = ENOSYS; return -1;
//		const struct timespec times[2], int flags, int fd, void *fdprivate) {
//}

int vunet_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_socket(int domain, int type, int protocol, void **fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_listen(int sockfd, int backlog, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_accept4(int sockfd, struct sockaddr *addr, socklen_t addrlen, int flags, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_getsockname(int sockfd, struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_getpeername(int sockfd, struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen,
		void *msg_control, size_t msg_controllen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_recvfrom(int sockfd, void *buf, size_t len, int flags,
		const struct sockaddr *src_addr, socklen_t addrlen,
		void *msg_control, size_t *msg_controllen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t *optlen, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_close(int fd, void *fdprivate) {
	errno = ENOSYS; return -1;
}

int vunet_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	errno = ENOSYS; return -1;
}

int vunet_umount2(const char *target, int flags) {
	errno = ENOSYS; return -1;
}

static void *vunet_default_clone(void *arg) {
  if (vunet_default != NULL) {
    pthread_rwlock_wrlock(&vunet_default->lock);
    vunet_default->count++;
    pthread_rwlock_unlock(&vunet_default->lock);
    return vunet_default;
  } else
    return NULL;
}

static void vunet_default_terminate(void) {
  if (vunet_default != NULL) {
    pthread_rwlock_wrlock(&vunet_default->lock);
    vunet_default->count -= 1;
    if (vunet_default->count == 0) {
      struct vunet_default_t *old_vunet_default = vunet_default;
      vunet_default = NULL;
      pthread_rwlock_unlock(&old_vunet_default->lock);
      pthread_rwlock_destroy(&old_vunet_default->lock);
      free(old_vunet_default);
    } else
      pthread_rwlock_unlock(&vunet_default->lock);
  }
}


static void *vunet_tracer_upcall(mod_inheritance_state_t state, void *arg) {
  void *ret_value = NULL;
  switch (state) {
    case MOD_INH_CLONE:
      ret_value = vunet_default_clone(arg);
      break;
    case MOD_INH_START:
      vunet_default = arg;
      break;
    case MOD_INH_EXEC:
      break;
    case MOD_INH_TERMINATE:
      vunet_default_terminate();
      break;
  }
  return ret_value;
}

void *vunet_init (void) {
	mod_inheritance_upcall_register(vunet_tracer_upcall);
	return NULL;
}

int vunet_fini(void *private) {
	return 0;
}

