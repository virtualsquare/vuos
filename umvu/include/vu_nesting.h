#ifndef VU_NESTING_H
#define VU_NESTING_H

/* enable and disable nested virtualization */
void vu_nesting_enable(void);
void vu_nesting_disable(void);

/* vu_nesting_init enables the self virtualization using libpurelibc.
	 vuos supports nested virtualization using self virtualization.
	 This function execs and then restarts the entire hypervisor
	 to enable LD_PRELOAD of libpurelibc */

/* If libpurelibc.so is not preloaded, this function add it to LD_PRELOAD and
	 umvu re-execute itself.
	 The nested virtualization is enabled during the "second execution".  In this
	 way purelibc is loaded at the top of the library hierarchy allowing its
	 functions implementation to prevail over the other libraries functions.*/


void vu_nesting_init(int argc, char **argv);

#endif

