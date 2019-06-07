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
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <vumodule.h>
#include <vunet.h>

VU_PROTOTYPES(vunet)

	struct vu_module_t vu_module = {
		.name = "vunet",
		.description = "vu virtual networking"
	};

struct vunet_default_t {
  pthread_rwlock_t lock;
  size_t count;
	struct vunet *defstack[AF_MAX + 1];
};

static __thread struct vunet_default_t *vunet_default = NULL;
static void vu_default_modify_lock(void);
static void vu_default_read_lock(void);
static void vu_default_unlock(void);

struct vunet {
	void *dlhandle;
	struct vunet_operations *netops;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	time_t mounttime;
	time_t atime;
	struct vuht_entry_t *socket_ht;
	struct vuht_entry_t *ioctl_ht;
	struct vuht_entry_t *path_ht;
	void *private_data;
};

struct vunetfd {
	struct vunet *vunet;
	void *netfdprivate;
};

static __thread struct vunetfd *current_vnetfd = NULL;

void *vunet_get_fdprivate(void) {
	if (current_vnetfd == NULL)
		return NULL;
	else
		return current_vnetfd->netfdprivate;
}

void vunet_set_fdprivate(void *fdprivate) {
	if (current_vnetfd != NULL)
		current_vnetfd->netfdprivate = fdprivate;
}

void *vunet_get_private_data(void) {
	struct vunet *vunet = vu_get_ht_private_data();
	if (vunet == NULL)
		return NULL;
	else
		return vunet->private_data;
}

static struct vunet *get_defstack(int domain) {
	if (domain >= 0 && domain <= AF_MAX) {
		if (vunet_default != NULL) {
			struct vunet *vunet;
			vu_default_read_lock();
			vunet = vunet_default->defstack[domain];
			vu_default_unlock();
			return vunet;
		} else
			return NULL;
	} else
		return NULL;
}

static void set_defstack(int domain, struct vunet *vunet) {
	if (domain >= 0 && domain <= AF_MAX) {
		vu_default_modify_lock();
		if (domain == PF_UNSPEC) {
			for (domain = 0; domain <= AF_MAX; domain++) {
				if (vunet->netops->supported_domain == NULL ||
						vunet->netops->supported_domain(domain))
					vunet_default->defstack[domain] = vunet;
			}
		} else
			vunet_default->defstack[domain] = vunet;
		vu_default_unlock();
	}
}

/* confirmation function for sockets */
static int checksocket(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	struct vunet *vunet = vuht_get_private_data(ht);
	int *domain = arg;
	struct vunet *defvunet = get_defstack(*domain);
	/* if the default stack for this process is this, then ok else skip */
	if (vunet == defvunet) {
		return 1;
	} else {
		return 0;
	}
}

/* confirmation function for ioctl */
static int checkioctl(uint8_t type, void *arg, int arglen,
    struct vuht_entry_t *ht) {
	unsigned long *request = arg;
	struct vunet *vunet = vuht_get_private_data(ht);
	struct vunet *defvunet = get_defstack(PF_NETLINK);
	/* if the default stack for this process is this AND
		 the request is supported, then ok else skip */
	if (vunet->netops->supported_ioctl != NULL &&
			vunet->netops->supported_ioctl(*request) &&
			vunet == defvunet)
		return 1;
	else
		return 0;
}

int vu_vunet_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *fdprivate) {
	struct vunet *vunet = vu_get_ht_private_data();

	memset(buf, 0, sizeof(struct vu_stat));
	buf->st_mode = vunet->mode;
	buf->st_uid = vunet->uid;
	buf->st_gid = vunet->gid;
	buf->st_mtime = vunet->mounttime;
	buf->st_atime = vunet->atime;
	return 0;
}

//int vu_vunet_access(char *path, int mode, int flags) {
//	/* access control */
//	return 0;
//}

int vu_vunet_chmod(const char *pathname, mode_t mode, int fd, void *fdprivate) {
	struct vunet *vunet = vu_get_ht_private_data();

	/* access control */
	vunet->mode = (vunet->mode & S_IFMT) | (mode & (S_IRWXU | S_IRWXG | S_IRWXO));
	return 0;
}

int vu_vunet_lchown(const char *pathname, uid_t owner, gid_t group, int fd, void *fdprivate) {
	struct vunet *vunet = vu_get_ht_private_data();

	/* access control */
	if (owner != (uid_t) -1)
		vunet->uid = owner;
	if (group != (gid_t) -1)
		vunet->gid = group;
	return 0;
}

int vu_vunet_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event, void *fdprivate) {
	current_vnetfd = fdprivate;
	if (current_vnetfd->vunet->netops->epoll_ctl == NULL)
    return errno = ENOSYS, -1;
  else
		return current_vnetfd->vunet->netops->epoll_ctl(epfd, op, fd, event);
}

int vu_vunet_socket(int domain, int type, int protocol, void **fdprivate) {
	struct vunet *vunet = vu_get_ht_private_data();
	if (vunet == NULL)
		vunet = get_defstack(domain);
	if (vunet == NULL)
		return errno = EAFNOSUPPORT, -1;
	printkdebug(N, "socket stack %p domain 0x%x type 0x%x protocol 0x%x",
			vunet, domain, type, protocol);
	if (type == SOCK_DEFAULT) {
		set_defstack(domain, vunet);
		return 0;
	} else {
		if (vunet->netops->socket == NULL)
			return errno = ENOSYS, -1;
		else if (vunet->netops->supported_domain != NULL &&
				! vunet->netops->supported_domain(domain))
			return errno = EAFNOSUPPORT, -1;
		else {
			current_vnetfd = malloc(sizeof(struct vunetfd));
			if (current_vnetfd == NULL)
				return errno = ENOMEM, -1;
			else {
				int retval;
				current_vnetfd->vunet = vunet;
				current_vnetfd->netfdprivate = NULL;
				retval = vunet->netops->socket(domain, type, protocol);
				if (retval >= 0) {
					printkdebug(N, "socket stack %p domain 0x%x type 0x%x protocol 0x%x -> %p",
							vunet, domain, type, protocol, current_vnetfd);
					*fdprivate = current_vnetfd;
				} else {
					free(current_vnetfd);
					current_vnetfd = NULL;
				}
				return retval;
			}
		}
	}
}

int vu_vunet_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "bind %p %d", current_vnetfd, sockfd);
	if (current_vnetfd->vunet->netops->bind == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->bind(sockfd, addr, addrlen);
}

int vu_vunet_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "connect %p %d", current_vnetfd, sockfd);
	if (current_vnetfd->vunet->netops->connect == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->connect(sockfd, addr, addrlen);
}

int vu_vunet_listen(int sockfd, int backlog, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "listen %p %d %d", sockfd, current_vnetfd, backlog);
	if (current_vnetfd->vunet->netops->listen == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->listen(sockfd, backlog);
}

int vu_vunet_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "accept4 %p %d", current_vnetfd, sockfd);
	if (current_vnetfd->vunet->netops->accept4 == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->accept4(sockfd, addr, addrlen, flags);
}

int vu_vunet_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "getsockname %p %d", current_vnetfd, sockfd);
	if (current_vnetfd->vunet->netops->getsockname == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->getsockname(sockfd, addr, addrlen);
}

int vu_vunet_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "getpeername %p %d", current_vnetfd, sockfd);
	if (current_vnetfd->vunet->netops->getpeername == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->getpeername(sockfd, addr, addrlen);
}

ssize_t vu_vunet_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen,
		void *msg_control, size_t msg_controllen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "sendto %p %d %p %d", current_vnetfd, sockfd, buf, len);
	if (current_vnetfd->vunet->netops->sendmsg == NULL)
    return errno = ENOSYS, -1;
  else {
		struct iovec iov[] = {{(void *) buf, len}};
		struct msghdr msgh = {(void *) dest_addr, addrlen, iov, 1, msg_control, msg_controllen, 0};
    return current_vnetfd->vunet->netops->sendmsg(sockfd, &msgh, flags);
	}
}

ssize_t vu_vunet_recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen,
		void *msg_control, size_t *msg_controllen, void *fdprivate) {
	  current_vnetfd = fdprivate;
	printkdebug(N, "recvfrom %p %d %p %d", current_vnetfd, sockfd, buf, len);
  if (current_vnetfd->vunet->netops->recvmsg == NULL)
    return errno = ENOSYS, -1;
  else {
		struct iovec iov[] = {{buf, len}};
		struct msghdr msgh = {(void *) src_addr, *addrlen, iov, 1, msg_control, 0, 0};
		if (msg_controllen != NULL)
			msgh.msg_controllen = *msg_controllen;
    int retval = current_vnetfd->vunet->netops->recvmsg(sockfd, &msgh, flags);
		if (retval >= 0) {
			if (addrlen != NULL)
				*addrlen = msgh.msg_namelen;
			if (msg_controllen != NULL)
				*msg_controllen = msgh.msg_controllen;
		}
		return retval;
	}
}

int vu_vunet_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "getsockopt %p %d %d %d", current_vnetfd, sockfd, level, optname);
	if (current_vnetfd->vunet->netops->getsockopt == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->getsockopt(sockfd, level, optname, optval, optlen);
}

int vu_vunet_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t optlen, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "setsockopt %p %d %d %d", current_vnetfd, sockfd, level, optname);
	if (current_vnetfd->vunet->netops->setsockopt == NULL)
		return errno = ENOSYS, -1;
	else
		return current_vnetfd->vunet->netops->setsockopt(sockfd, level, optname, optval, optlen);
}

int vu_vunet_ioctl(int sockfd, unsigned long request, void *buf, uintptr_t addr, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "ioctl %p %d 0x%x %p %d", current_vnetfd, sockfd, request, buf, addr);
	if (current_vnetfd == NULL) {
		struct vunet *vunet = vu_get_ht_private_data();
		if (vunet->netops->ioctl == NULL)
			return errno = ENOSYS, -1;
		else
			return vunet->netops->ioctl(sockfd, request, buf);
	} else {
		if (current_vnetfd->vunet->netops->ioctl == NULL)
			return errno = ENOSYS, -1;
		else
			return current_vnetfd->vunet->netops->ioctl(sockfd, request, buf);
	}
}

int vu_vunet_close(int sockfd, void *fdprivate) {
	current_vnetfd = fdprivate;
	printkdebug(N, "close %p %d", current_vnetfd, sockfd);
  if (current_vnetfd->vunet->netops->close == NULL)
    return errno = ENOSYS, -1;
  else
    return current_vnetfd->vunet->netops->close(sockfd);
}

int vu_vunet_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	void *dlhandle = vu_mod_dlopen(filesystemtype, RTLD_NOW);
	struct vunet_operations *netops;
	printkdebug(N, "mount \'%s\' \'%s\' %s", source, target, filesystemtype);
	if (dlhandle == NULL || (netops = dlsym(dlhandle, "vunet_ops")) == NULL) {
		if (dlhandle != NULL)
			dlclose(dlhandle);
		return errno = ENODEV, -1;
	} else {
		struct vu_service_t *s = vu_mod_getservice();
		struct vunet *vunet = malloc(sizeof(struct vunet));
		int retvalue = 0;
		if (vunet == NULL) {
			return errno = ENOMEM, -1;
		} else {
			vunet->dlhandle = dlhandle;
			vunet->netops = netops;
			vunet->mode = S_IFSTACK | 0777;
			vunet->uid = 0;
			vunet->gid = 0;
			vunet->mounttime = vunet->atime = time(NULL);
			vunet->private_data = NULL;
			errno = 0;
			if (vunet->netops->init != NULL)
				retvalue = vunet->netops->init(source, mountflags, data, &vunet->private_data);
			if (retvalue < 0) {
				free(vunet);
				if (errno == 0)
					errno = EINVAL;
				retvalue = -1;
			} else {
				if (vunet->netops->supported_ioctl)
					vunet->ioctl_ht = vuht_add(CHECKIOCTL, NULL, 0, s, checkioctl, vunet, 0);
				else
					vunet->ioctl_ht = NULL;
				vunet->socket_ht = vuht_add(CHECKSOCKET, NULL, 0, s, checksocket, vunet, 0);
				vunet->path_ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, vunet);
				printkdebug(N, "mount \'%s\' \'%s\' %s -> %p", source, target, filesystemtype, vunet);
			}
		}
		return retvalue;;
	}
}

/* XXX umount usage count (default defs) */
int vu_vunet_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
  struct vunet *vunet = vu_get_ht_private_data();
  int ret_value;
	printkdebug(N, "umount2 \'%s\' %p", target, vunet);
	vuht_del(vunet->socket_ht, flags);
	if (vunet->ioctl_ht)
		vuht_del(vunet->ioctl_ht, flags);
  if ((ret_value = vuht_del(ht, flags)) < 0)
    return errno = -ret_value, -1;
  return 0;
}

void vu_vunet_cleanup(uint8_t type, void *arg, int arglen,
		struct vuht_entry_t *ht) {
	struct vunet *vunet = vuht_get_private_data(ht);
	printkdebug(N, "cleanup %p %d", vunet, type);
  if (type == CHECKSOCKET)
		vunet->socket_ht = NULL;
  if (type == CHECKIOCTL)
		vunet->ioctl_ht = NULL;
  if (type == CHECKPATH)
		vunet->path_ht = NULL;
	if (vunet->socket_ht == NULL &&
			vunet->ioctl_ht == NULL &&
			vunet->path_ht == NULL) {
		if (vunet->netops->fini != NULL)
			vunet->netops->fini(vunet->private_data);
    free(vunet);
  }
}

static void vu_default_modify_lock(void) {
	if (vunet_default == NULL) {
		struct vunet_default_t *new;
		int i;
		new = malloc(sizeof(struct vunet_default_t));
		pthread_rwlock_init(&new->lock, NULL);
		new->count = 1;
		for (i = 0; i < AF_MAX + 1; i++)
			new->defstack[i] = NULL;
		vunet_default = new;
	}
	pthread_rwlock_wrlock(&vunet_default->lock);
	if (vunet_default->count > 1) {
		struct vunet_default_t *new;
    int i;
    new = malloc(sizeof(struct vunet_default_t));
    pthread_rwlock_init(&new->lock, NULL);
    new->count = 1;
    vunet_default->count -= 1;
    for (i = 0; i < AF_MAX + 1; i++)
      new->defstack[i] = vunet_default->defstack[i];
		pthread_rwlock_unlock(&vunet_default->lock);
    vunet_default = new;
		pthread_rwlock_wrlock(&vunet_default->lock);
  }
}

static void vu_default_read_lock(void) {
	pthread_rwlock_rdlock(&vunet_default->lock);
}

static void vu_default_unlock(void) {
	pthread_rwlock_unlock(&vunet_default->lock);
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

void *vu_vunet_init (void) {
	mod_inheritance_upcall_register(vunet_tracer_upcall);
	return NULL;
}

int vu_vunet_fini(void *private) {
	mod_inheritance_upcall_deregister(vunet_tracer_upcall);
	return 0;
}

__attribute__((constructor))
  static void init(void) {
		debug_set_name(N, "VUNET");
	}

__attribute__((destructor))
  static void fini(void) {
		debug_set_name(N, "");
	}

