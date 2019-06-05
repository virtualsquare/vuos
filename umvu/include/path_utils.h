#ifndef PATH_UTILS_H
#define PATH_UTILS_H

/* helper function to get a canonicalized path arguemnts from the user process.
	 return values, if not NULL, are dynamically allocated strings, so their memory must be
	 deallocated by free(3) */

char *get_path(int dirfd, syscall_arg_t addr, struct stat *buf, int flags, uint8_t *need_rewrite, int nested);

/* get the canonicalized path of the system call described is sd. It uses arch_table to
	 process -at calls, to decide if the system call follow synbolic links or not etc. */
char *get_syspath(struct syscall_descriptor_t *sd, struct stat *buf, uint8_t *need_rewrite);
/* the same as above for nested syscalls */
char *get_nested_syspath(int syscall_number, syscall_arg_t *args, struct stat *buf, uint8_t *need_rewrite);

/* the same as above for virtual syscalls */
char *get_vsyspath(struct syscall_descriptor_t *sd, struct stat *buf, uint8_t *need_rewrite);

/* change the path of a system call: rewrite the path in the user process memory.
	 The hosting kernel receives the system call request using the modified path.
	 The new path string is stored on the stack, just below the stack pointer */
void rewrite_syspath(struct syscall_descriptor_t *sd, char *newpath);

#endif
