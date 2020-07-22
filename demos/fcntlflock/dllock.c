#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

// define the types of the original flock functions to be used with dlsym
typedef int (*real_flock)(int, int);
typedef int (*real_fcntl)(int, int, ...);

// override the flock SC
int flock(int fd, int operation) {
	// check whether the call has to be BLOCKING
	int noblock = operation & LOCK_NB; 
	short fcntl_ltype;

	// tell fcntl whether to wait or not based on the LOCK_NB flag in operation
	int fcntl_cmd = noblock ? F_OFD_SETLK : F_OFD_SETLKW;

	switch (operation & ~LOCK_NB) {
		case LOCK_SH:	// apply SHARED lock
			fcntl_ltype = F_RDLCK;
			break;

		case LOCK_EX:	// apply EXCLUSIVE lock
			fcntl_ltype = F_WRLCK;
			break;

		case LOCK_UN:	// UNlock
			fcntl_ltype = F_UNLCK;
			break;

		default:		// operation is not valid
			errno = EINVAL;
			return -1;
	}

	struct flock lockinfo = { fcntl_ltype, SEEK_SET, 0, 0, 0 };
	int res = fcntl(fd, fcntl_cmd, &lockinfo);
	int errno_backup = errno;
	int new_errno;

	if (res < 0) {
		// the error generated when a call results in entering a waiting state
		// is different between flock and fcntl
		if (errno == EACCES || errno == EAGAIN) {
			errno = EWOULDBLOCK;
		}

		/*
		 * TODO: flock can apply locks regardless of the open mode of the target file,
		 * whereas fcntl locks must be applied to files which open mode match the
		 * desired lock type (READ for READ locks, etc.).
		 * In such cases fcntl raises an EBADF error, while flock successfully applies
		 * the lock so the behaviour of this method should change accordingly (assuming
		 * it is possible).
		 */

		return -1;
	}

	//return ((real_flock)dlsym(RTLD_NEXT, "flock"))(fd, operation);
	return 0;
}
	
int fcntl(int fd, int cmd, ...) {
	va_list ap;
	struct flock *lockinfo;
	int res;
	int errno_backup;
	struct f_owner_ex *ownp_arg;
	int int_arg;
	uint64_t *uint_argp;

	// get the actual fcntl function address
	real_fcntl r_fcntl = dlsym(RTLD_NEXT, "fcntl");
	va_start(ap, cmd);

	switch (cmd) {
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case F_OFD_SETLK:
		case F_OFD_SETLKW:
		case F_OFD_GETLK:
			// retrieve the flock struct pointer from the variadic parameter
			lockinfo = va_arg(ap, struct flock *);
			res = r_fcntl(fd, cmd, lockinfo);
			break;

		case F_GETOWN_EX:
		case F_SETOWN_EX:
			ownp_arg = va_arg(ap, struct f_owner_ex *);
			res = r_fcntl(fd, cmd, ownp_arg);
			break;

		case F_GET_RW_HINT:
		case F_SET_RW_HINT:
		case F_GET_FILE_RW_HINT:
		case F_SET_FILE_RW_HINT:
			uint_argp = va_arg(ap, uint64_t *);
			res = r_fcntl(fd, cmd, uint_argp);
			break;

		default:	// all fcntl calls that require an int as third argument
			int_arg = va_arg(ap, int);
			res = r_fcntl(fd, cmd, int_arg);
			break;
	}

	errno_backup = errno;
	va_end(ap);
	errno = errno_backup;
	return res;
}

