#ifndef VU_NESTING_H
#define VU_NESTING_H

/**Enabling nested virtualization via purelibc.
	If libpurelibc.so is not setted in LD_PRELOAD, this function sets it and umvu re-execute itself.
	During the "second execution" (or if libpurelibc was setted) purelic is dynamic linked and nested virtualization is enabled.

	Loading purelibc in this way, puts it at the top of libraries hierarchy allowing its functions implementation to prevail over the other
	libraries functions.*/
void vu_nesting_init(int argc, char *argv);

#endif

