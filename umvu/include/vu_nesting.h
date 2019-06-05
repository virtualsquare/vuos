#ifndef VU_NESTING_H
#define VU_NESTING_H

/* enable and disable nested virtualization */
void vu_nesting_enable(void);
void vu_nesting_disable(void);

/* enables the self virtualization using libpurelibc.
	 vuos support nested virtualization using slft virtualization.
	 This function execs and then restarts the entire hypervisor
	 to enable LD_PRELOAD of libpurelibc */
void vu_nesting_init(int argc, char **argv);

#endif

