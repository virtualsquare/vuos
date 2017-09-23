#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <ctype.h>

#include <linux_32_64.h>
//#include <canonicalize.h>
#include <vu_log.h>
//#include <vu_tmpdir.h>
//#include <vu_pushpop.h>
//#include <r_table.h>
#include <umvu_peekpoke.h>
//#include <umvu_tracer.h>
#include <hashtable.h>
#include <arch_table.h>
#include <syscall_defs.h>
#include <vu_execute.h>
#include <service.h>
//#include <path_utils.h>
#include <vu_file_table.h>
#include <vu_fd_table.h>
#include <vu_wrapper_utils.h>

static void resize_mmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd, 
	 struct fnode_t *fnode) {
	int sfd;
	void *private;
	int ret_value;
	struct vu_stat statbuf;
	epoch_t e;
	sfd = (vu_fnode_get_sfd(fnode, &private));
	e = set_vepoch(vuht_get_vepoch(ht));
	ret_value = service_syscall(ht, __VU_lstat)(sd->extra->path, &statbuf, 0, sfd, private);
	set_vepoch(e);
	if (ret_value >= 0) {
		printk("SIZE = %d\n", statbuf.st_size);
		vu_fnode_setminsize(fnode, statbuf.st_size);
	}
}

void wi_mmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	//printk("mmap2 fd = %d  ht = %x\n", sd->syscall_args[4], ht);
	int fd = sd->syscall_args[4];
	int nested = sd->extra->nested;
	if (ht && fd >= 0) { // nothing to do if the file is real or is not on a file
		struct fnode_t *fnode = vu_fd_mmapdup(fd, nested);
		resize_mmap(ht, sd, fnode);
		sd->inout = fnode;
#if 0
		size_t length = sd->syscall_args[1];
		int prot = sd->syscall_args[2];
		int flags = sd->syscall_args[3];
		off_t offset = sd->syscall_args[5];

		if (sd->syscall_number == __NR_mmap2)
			offset = offset * umvu_get_pagesize;

		// copy in from fd [offset -- offset+length] (to the vnode tmp file)
		// what if the same file region is mmapped several times?
		// it would be a better choice to copy in from the file in wo_mmap
		// (truncate the file to the actual file size...)
		// does mmap upload pages at mmap time or it is lazy?	
		// it is possible to check if the same region is already mapped...

#endif
		sd->action = DOIT_CB_AFTER;
	} else
		sd->inout = NULL;
}

void wo_mmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	struct fnode_t *fnode = sd->inout;
	if (fnode != NULL) {
		uintptr_t addr = sd->orig_ret_value;
		if (addr != (uintptr_t) -1) {
			size_t length = sd->syscall_args[1];
			int prot = sd->syscall_args[2];
			int flags = sd->syscall_args[3];
			off_t offset = sd->syscall_args[5];
#ifdef __NR_mmap2
			if (sd->syscall_number == __NR_mmap2)
				offset = offset * umvu_get_pagesize();
#endif
			//printk("mmap %x %d %d %p\n", addr, length, offset, fnode);
		} else
			vu_fnode_close(fnode);
	}
	sd->ret_value = sd->orig_ret_value;
}

void wi_mm_cb_after(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->action = DOIT_CB_AFTER;
}

void wo_munmap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}

void wo_mremap(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}

void wo_msync(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
}
