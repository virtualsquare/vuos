#ifndef PATH_UTILS_H
#define PATH_UTILS_H

/**Getting pathnames in a canonical form..*/

char *get_path(int dirfd, syscall_arg_t addr, struct stat *buf, int flags);
char *get_syspath(struct syscall_descriptor_t *sd, struct stat *buf);
void rewrite_syspath(struct syscall_descriptor_t *sd, char *newpath);
char *get_vsyspath(struct syscall_descriptor_t *sd, struct stat *buf);
char *get_nested_path(int dirfd, char *path, struct stat *buf,int flags);
char *get_nested_syspath(int syscall_number, syscall_arg_t *args, struct stat *buf);

#endif
