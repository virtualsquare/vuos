#ifndef VU_TMPDIR_h
#define VU_TMPDIR_h

/** Each umvu hypervisor can open a support directory in /tmp, using it  mainly to open virtual files. */

char *vu_tmpdirpath(void);

#endif
