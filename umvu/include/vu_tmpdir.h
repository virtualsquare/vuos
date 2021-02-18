#ifndef VU_TMPDIR_h
#define VU_TMPDIR_h

/* Each umvu instance uses a hidden directory in /tmp to store temporary files.
	 This function returns the path of that directory */
char *vu_tmpdirpath(void);

#endif
