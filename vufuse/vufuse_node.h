#ifndef VUFUSE_NODE_H
#define VUFUSE_NODE_H

struct fuse;
struct fuse_node;

char *vufuse_node_path(struct fuse_node *node);
struct fuse_node *vufuse_node_add(struct fuse *fuse, const char *path);
char *vufuse_node_del(struct fuse_node *node);
char *vufuse_node_rename(struct fuse *fuse, const char *path, const char *newpath);

#endif
