#ifndef VUMISC_H
#define VUMISC_H
#include <libvumod.h>
#include <vumodule.h>

struct vumisc_info {
  char *path;
  struct vu_stat stat;
  void *upcall_private;
};

/* get the private data (return value of "init") */
void *vumisc_get_private_data(void);

struct vumisc_operations_t {
	struct vumisc_info *infotree;
	pseudo_upcall infocontents;
	/* constructor/destructor of the submodule.
	 * the return value of init:
	 *   - can be retrieved by vudev_get_private_data()
	 *   - is the private_data argument of fini */
	void * (*init) (const char *source);
	int (*fini) (void *private_data);
};

#define VUMISC_SYSNAME(name, syscall) name ## _ ## syscall

#define VUMISC_PROTOTYPES(name) \
	int VUMISC_SYSNAME(name, clock_getres) (clockid_t clk_id, struct timespec *res); \
	int VUMISC_SYSNAME(name, clock_gettime) (clockid_t clk_id, struct timespec *tp); \
	int VUMISC_SYSNAME(name, clock_settime) (clockid_t clk_id, const struct timespec *tp); \

#endif
