#include <stdio.h>
struct fuse_operations;
struct fuse_args;
struct libfuse_version;

int __fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size, void *user_data);
int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size, void *user_data) {
	return __fuse_main_real(argc, argv, op, op_size, user_data);
}
int fuse_main_real_versioned(int argc, char *argv[],
           const struct fuse_operations *op, size_t op_size,
           struct libfuse_version *version, void *user_data) {
	return __fuse_main_real(argc, argv, op, op_size, user_data);
}

struct fuse *__fuse_new(struct fuse_args *args,
    const struct fuse_operations *op, size_t op_size,
    void *user_data);
struct fuse *fuse_new(struct fuse_args *args,
    const struct fuse_operations *op, size_t op_size,
    void *user_data) {
	return __fuse_new(args, op, op_size, user_data);
}
struct fuse *_fuse_new_30(struct fuse_args *args,
        const struct fuse_operations *op, size_t op_size,
        struct libfuse_version *version, void *user_data) {
	return __fuse_new(args, op, op_size, user_data);
}
struct fuse *_fuse_new_31(struct fuse_args *args,
        const struct fuse_operations *op, size_t op_size,
        struct libfuse_version *version, void *user_data) {
	return __fuse_new(args, op, op_size, user_data);
}
