#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <r_table.h>
#include <vu_log.h>
#include <vu_initfini.h>
#include <vu_tmpdir.h>

#define TMP_PATTERN "/tmp/.vu_%010lu_XXXXXX"
#define TMP_PATTERN_EXAMPLE "/tmp/.vu_0123456789_XXXXXX"
static char dirpath[sizeof(TMP_PATTERN_EXAMPLE)+1];

char *vu_tmpfilename(dev_t dev, ino_t inode) {
	char *ret_value;
	unsigned long ldev = dev;
  unsigned long linode = inode;
	asprintf(&ret_value, "%s/%lx_%lx", dirpath, ldev, linode);
	return ret_value;
}

char *vu_tmpdirpath(void) {
	return dirpath;
}

static void dirpath_init(void) {
	snprintf(dirpath, sizeof(TMP_PATTERN_EXAMPLE)+1, TMP_PATTERN, (unsigned long) getpid());
	fatal(mkdtemp(dirpath));
	r_chdir(dirpath);
}

static void dirpath_fini(void) {
	r_rmdir(dirpath);
}

__attribute__((constructor))
	static void init (void) {
		vu_constructor_register(dirpath_init);
		vu_destructor_register(dirpath_fini);
	}
