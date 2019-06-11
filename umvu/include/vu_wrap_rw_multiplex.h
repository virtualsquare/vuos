#ifndef VU_WRAP_RW_MULTIPLEX_H
#define VU_WRAP_RW_MULTIPLEX_H
#include <sys/stat.h>
#include <syscall_table.h>

/* this hypervisor module defines the wrappers for read and write and
	 dispatch the requests to specific wrappersdepending on the file types.

	 e.g. read and write have different implementations when operating
	 on regular files, block or char devices.
	 read/write are mapped to recvmsg/sendmsg if the file is a socket.

	 The following functions permits the definition of specific handlers
	 per file type */

void multiplex_read_wrappers(mode_t mode,
		wrapf_t wrapin, wrapf_t wrapduring, wrapf_t wrapout);
void multiplex_write_wrappers(mode_t mode,
		wrapf_t wrapin, wrapf_t wrapduring, wrapf_t wrapout);

#endif
