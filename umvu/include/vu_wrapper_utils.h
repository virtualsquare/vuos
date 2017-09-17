#ifndef VU_WRAPPER_UTILS_H
#define VU_WRAPPER_UTILS_H
#include <stdlib.h>
#include <xcommon.h>

/* macro for wrappers.
 * stucture for read wrappers/large buffers:
 *    vu_alloc_arg(addr, var, size, nested)
 *    vu_poke_arg(addr, var, size, nested)
 *    vu_free_arg(var, nested)
 * stucture for write wrappers/large buffers:
 *    vu_peek_alloc_arg(addr, var, size, nested)
 *    vu_free_arg(var, nested)
 * stucture for read wrappers/small buffers (stack allocation)
 *    vu_alloc_local_arg(addr, var, size, nested)
 *    vu_poke_arg(addr, var, size, nested)
 * stucture for write wrappers/small buffers (stack allocation)
 *    vu_peek_alloc_local_arg(addr, var, size, nested)
 * warning: local_arg macros define a local var.
 */

#define vu_alloc_arg(addr, var, size, nested) \
	do { \
		if (nested) { \
			var = (typeof(var)) addr; \
		} else { \
			if (!nested) var = malloc(size); \
		} \
	} while(0)

#define vu_peek_alloc_arg(addr, var, size, nested) \
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
			var = (typeof(var)) __ ## var \
			umvu_peek_data(addr, var, size); \
		} \
	} while(0)

#define vu_poke_arg(addr, var, size, nested) \
	if (!nested) umvu_poke_data(addr, var, size);

#define vu_free_arg(var, nested) \
	if (!nested) xfree(var)

#endif

