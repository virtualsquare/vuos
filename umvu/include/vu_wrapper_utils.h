#ifndef VU_WRAPPER_UTILS_H
#define VU_WRAPPER_UTILS_H
#include <stdlib.h>
#include <xcommon.h>
#include <sys/uio.h>

/* macro for wrappers.
 * stucture for read wrappers/large buffers:
 *    vu_alloc_arg(addr, var, size, nested)
 *    vu_poke_arg(addr, var, size, nested)
 *    vu_free_arg(var, nested)
 * stucture for write wrappers/large buffers:
 *    vu_alloc_peek_arg(addr, var, size, nested)
 *    vu_free_arg(var, nested)
 * stucture for read wrappers/small buffers (stack allocation)
 *    vu_alloc_local_arg(addr, var, size, nested)
 *    vu_poke_arg(addr, var, size, nested)
 * stucture for write wrappers/small buffers (stack allocation)
 *    vu_alloc_peek_local_arg(addr, var, size, nested)
 * stucture for read wrappers IOVEC
 *    vu_alloc_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested)
 *          it assigns buf and bufsize...
 *    vu_poke_iov_arg(iovaddr, iov, iovcnt, buf, len, nested)
 *    vu_free_iov_arg(iov, buf, nested)
 * stucture for write wrappers IOVEC
 *    vu_alloc_peek_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested)
 *    vu_free_iov_arg(iov, buf, nested)
 * warning: local_arg macros define a local var.
 */

#define vu_alloc_arg(addr, var, size, nested) \
	do { \
		if (nested) { \
			var = (typeof(var)) addr; \
		} else { \
			var = malloc(size); \
		} \
	} while(0)

#define vu_alloc_peek_arg(addr, var, size, nested) \
	do { \
		if (nested) { \
			var = (typeof(var)) addr; \
		} else { \
			var = malloc(size); \
			umvu_peek_data(addr, var, size); \
		} \
	} while(0)

#if 0
#define vu_peek_local_arg(addr, var, count, nested) \
	typeof(* var) __ ## var[(nested) ? 0 : count]; \
	var = (nested) ? (typeof(var)) addr : __ ## var
#endif
#define vu_alloc_local_arg(addr, var, size, nested) \
	char *__ ## var[(nested) ? 0 : size]; \
	var = (nested) ? (typeof(var)) addr : (typeof(var)) __ ## var

#define vu_alloc_peek_local_arg(addr, var, size, nested) \
	char *__ ## var[(nested) ? 0 : size]; \
	do { \
		if (nested) {\
			var = (typeof(var)) addr; \
		} else { \
			var = (typeof(var)) __ ## var ;\
			umvu_peek_data(addr, var, size); \
		} \
	} while(0)

#define vu_alloc_peek_local_strarg(addr, var, size, nested) \
	char *__ ## var[(nested) ? 0 : size]; \
	do { \
		if (nested) {\
			var = (typeof(var)) addr; \
		} else { \
			var = (typeof(var)) __ ## var ;\
			umvu_peek_str(addr, var, size); \
		} \
	} while(0)

#define vu_poke_arg(addr, var, size, nested) \
	if (!nested) umvu_poke_data(addr, var, size)

#define vu_peek_arg(addr, var, size, nested) \
	if (!nested) umvu_peek_data(addr, var, size)

#define vu_free_arg(var, nested) \
	if (!nested) xfree(var)

__attribute__((always_inline))
	static inline size_t iovec_bufsize(struct iovec *iov, int iovcnt) {
		int i;
		size_t ret_value = 0;
		for (i = 0; i < iovcnt; i++)
			ret_value += iov[i].iov_len;
		return ret_value;
	}

__attribute__((always_inline))
	static inline void vu_peek_iov_arg(uintptr_t iovaddr,
			struct iovec *iov, int iovcnt, void *buf, int nested) {
		char *cbuf = (char *) buf;
		int i;
		for (i = 0; i < iovcnt; i++) {
			ssize_t len = iov[i].iov_len;
			vu_peek_arg((uintptr_t) iov[i].iov_base, cbuf, len, nested);
			cbuf += len;
		}
	}

__attribute__((always_inline))
	static inline void vu_poke_iov_arg(uintptr_t iovaddr,
      struct iovec *iov, int iovcnt, void *buf, size_t len, int nested) {
		int i;
    char *cbuf = (char *) buf;
		for (i = 0; i < iovcnt && len > 0; i++) {
			size_t iov_len = iov[i].iov_len;
			if (len < iov_len) iov_len = len;
			vu_poke_arg((uintptr_t) iov[i].iov_base, cbuf, iov_len, nested);
			len -= iov_len;
			cbuf += iov_len;
		}
	}

#define vu_alloc_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested) \
	do { \
		vu_alloc_peek_arg(iovaddr, iov, sizeof(struct iovec) * iovcnt, nested); \
		bufsize = iovec_bufsize(iov, iovcnt); \
		buf = malloc(bufsize); \
	} while(0)

#define vu_alloc_peek_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested) \
	do { \
		vu_alloc_iov_arg(iovaddr, iov, iovcnt, buf, bufsize, nested); \
		vu_peek_iov_arg(iovaddr, iov, iovcnt, buf, nested); \
	} while(0)

#define vu_free_iov_arg(iov, buf, nested) \
	do {\
		vu_free_arg(iov, nested); \
    xfree(buf); \
  } while(0)

#endif

