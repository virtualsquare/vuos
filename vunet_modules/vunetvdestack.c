#include <vunet.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <libvdeplug.h>
#include <r_table.h>

/* just in case prctl.h is not providing these definitions */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT      47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE  2
#endif
#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER  3
#endif

#define APPSIDE 0
#define DAEMONSIDE 1

#define DEFAULT_IF_NAME "vde0"

#define CHILD_STACK_SIZE (256 * 1024)


struct vdestack {
	pid_t pid;
  int cmdpipe[2]; // socketpair for commands;
	VDECONN *vdeconn;
	 char *child_stack;
  char ifname[];
};

struct vdecmd {
  int domain;
  int type;
  int protocol;
};

struct vdereply {
  int rval;
  int err;
};

static int open_tap(char *name) {
  struct ifreq ifr;
  int fd=-1;
  if((fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) < 0)
    return -1;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
  if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int childFunc(void *arg)
{
  struct vdestack *stack = arg;
	int n;
  char buf[VDE_ETHBUFSIZE];
	int tapfd = open_tap(stack->ifname);
  VDECONN *conn = stack->vdeconn;
	struct pollfd pfd[] = {{stack->cmdpipe[DAEMONSIDE], POLLIN, 0},
		{tapfd, POLLIN, 0},
		{vde_datafd(conn), POLLIN, 0}};
	if (tapfd  < 0) {
		perror("tapfd"); _exit(1);
	}
	pfd[1].fd = tapfd;
	while (r_poll(pfd, 3, -1) >= 0) {
		//printk("poll in %d %d %d\n",pfd[0].revents,pfd[1].revents,pfd[2].revents);
		if (pfd[0].revents & POLLIN) {
			struct vdecmd cmd;
			struct vdereply reply;
			int n;
			if ((n = r_read(stack->cmdpipe[DAEMONSIDE], &cmd, sizeof(cmd))) > 0) {
				reply.rval = r_socket(cmd.domain, cmd.type, cmd.protocol);
				reply.err = errno;
				r_write(stack->cmdpipe[DAEMONSIDE], &reply, sizeof(reply));
			} else
				break;
		}
		if (pfd[1].revents & POLLIN) {
			n = r_read(tapfd, buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vde_send(conn, buf, n, 0);
		}
		if (pfd[2].revents & POLLIN) {
			n = vde_recv(conn, buf, VDE_ETHBUFSIZE, 0);
			if (n == 0) break;
			r_write(tapfd, buf, n);
		}
		//printk("poll out\n");
	}
  r_close(stack->cmdpipe[DAEMONSIDE]);
	_exit(EXIT_SUCCESS);
}

struct vdestack *vde_addstack(char *vdenet, char *ifname) {
	  char *ifnameok = ifname ? ifname : DEFAULT_IF_NAME;
  size_t ifnameoklen = strlen(ifnameok);
  struct vdestack *stack = malloc(sizeof(*stack) + ifnameoklen + 1);

  if (stack) {
		strncpy(stack->ifname, ifnameok, ifnameoklen + 1);
		stack->child_stack = malloc(CHILD_STACK_SIZE);
    if (stack->child_stack == NULL)
      goto err_child_stack;

		if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, stack->cmdpipe) < 0)
      goto err_cmdpipe;

		if ((stack->vdeconn = vde_open(vdenet, "vdestack", NULL)) == NULL)
        goto err_vdenet;

		stack->pid = clone(childFunc, stack->child_stack + CHILD_STACK_SIZE,
        CLONE_VM | CLONE_FILES | CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD, stack);
    if (stack->pid == -1)
      goto err_child;
    //uid_gid_map(stack->pid); //is this required?
	}
	return stack;
err_child:
err_vdenet:
	r_close(stack->cmdpipe[APPSIDE]);
	r_close(stack->cmdpipe[DAEMONSIDE]);
err_cmdpipe:
	free(stack->child_stack);
err_child_stack:
  free(stack);
  return NULL;
}

void vde_delstack(struct vdestack *stack) {
	vde_close(stack->vdeconn);
	r_close(stack->cmdpipe[APPSIDE]);
	waitpid(stack->pid, NULL, 0);
	free(stack->child_stack);
  free(stack);
}

int vde_msocket(struct vdestack *stack, int domain, int type, int protocol) {
	struct vdecmd cmd = {domain, type, protocol};
  struct vdereply reply;

  r_write(stack->cmdpipe[APPSIDE],  &cmd, sizeof(cmd));
  r_read(stack->cmdpipe[APPSIDE], &reply, sizeof(reply));

  if (reply.rval < 0)
    errno = reply.err;
  return reply.rval;
}

static int supported_domain (int domain) {
	switch (domain) {
		case AF_INET:
		case AF_INET6:
		case AF_NETLINK:
		case AF_PACKET:
			return 1;
		default:
			return 0;
	}
}

int vdestack_socket(int domain, int type, int protocol) {
	struct vdestack *vdestack = vunet_get_private_data();
	return vde_msocket(vdestack, domain, type, protocol);
}

int vdestack_init(const char *source, unsigned long flags, const char *args, void **private_data) {
	struct vdestack *vdestack = vde_addstack((char *) source, NULL);
	*private_data = vdestack;
	return 0;
}

int vdestack_fini(void *private_data) {
	vde_delstack(private_data);
	return 0;
}

struct vunet_operations vunet_ops = {
	.socket = vdestack_socket,
	.bind = bind,
	.connect = connect,
	.listen = listen,
	.accept4 = accept4,
	.getsockname = getsockname,
	.getpeername = getpeername,
	.recvmsg = recvmsg,
	.sendmsg = sendmsg,
	.getsockopt = getsockopt,
	.setsockopt = setsockopt,
	.shutdown = shutdown,
	.ioctl = ioctl,
	.close = close,

	.epoll_ctl = epoll_ctl,

	.supported_domain = supported_domain,
	.init = vdestack_init,
	.fini = vdestack_fini,
};
