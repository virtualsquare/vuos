/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *                       Leonardo Frioli <leonardo.frioli@studio.unibo.it>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <vufuse_node.h>

#define NODE_HASH_SIZE 128
#define NODE_HASH_MASK (NODE_HASH_SIZE-1)

struct fuse_node {
  char *path;
  struct fuse *fuse;
  long hashsum;
  int open_count;
  struct fuse_node **pprevhash,*nexthash;
};

static pthread_mutex_t node_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct fuse_node *node_head[NODE_HASH_SIZE];

#define ADDRESS_LEN ((int)(sizeof(uintptr_t) * 2))
#define HIDDEN_PREFIX_LEN (6 + ADDRESS_LEN)

char *node_hiddenpath(struct fuse *fuse)
{
  char *name;
  static unsigned long hiddencount;
  asprintf(&name,"/.fuse%0*lx%010lu", ADDRESS_LEN, (uintptr_t)fuse, hiddencount++);
  return name;
}

static inline int node_hiddenpathcheck(struct fuse *fuse, const char *path)
{
  char check[HIDDEN_PREFIX_LEN + 1];
  snprintf(check,HIDDEN_PREFIX_LEN + 1,"/.fuse%0*lx", ADDRESS_LEN, (uintptr_t) fuse);
  return (strncmp(path,check,HIDDEN_PREFIX_LEN) == 0);
}


static inline long vnode_hash_sum(struct fuse *fuse, const char *path) {
  long sum = (long) fuse;
  while (*path != 0) {
    sum ^= ((sum << 5) + (sum >> 2) + *path);
    path++;
  }
  return sum;
}

static inline int vnode_hash_mod(long sum)
{
  return sum & NODE_HASH_MASK;
}

static inline struct fuse_node *node_find(void *fuse, const char *path,
    long hashsum, int hashkey)
{
  struct fuse_node *scan=node_head[hashkey];
  //printk("node_find %s\n",path);
  while (scan != NULL) {
  //printk("node_find_scan %s\n",path,scan->path);
    if (scan->hashsum == hashsum && scan->fuse == fuse &&
        strcmp(scan->path, path) == 0)
      return scan;
    scan=scan->nexthash;
  }
  return NULL;
}

char *node_path(struct fuse_node *node) {
	return node->path;
}

struct fuse_node *node_add(struct fuse *fuse, const char *path) {
	long hashsum = vnode_hash_sum(fuse, path);
  int hashkey = vnode_hash_mod(hashsum);
  struct fuse_node *new;
	pthread_mutex_lock(&node_mutex);
	new	= node_find(fuse, path, hashsum, hashkey);
	if (new != NULL)
		new->open_count++;
	else {
		new = malloc(sizeof (struct fuse_node));
    if (new != NULL) {
			new->path = strdup(path);
			new->fuse = fuse;
			new->hashsum = hashsum;
			new->open_count = 1;
			if (node_head[hashkey] != NULL)
				node_head[hashkey]->pprevhash = &(new->nexthash);
      new->nexthash = node_head[hashkey];
      new->pprevhash = &(node_head[hashkey]);
      node_head[hashkey] = new;
		} 
	}
	pthread_mutex_unlock(&node_mutex);
	return new;
}

char *node_del(struct fuse_node *old) {
	char *ret_value = NULL;
  pthread_mutex_lock(&node_mutex);
	if (old) {
		old->open_count--;
		if (old->open_count <= 0) {
			*(old->pprevhash)=old->nexthash;
			if (old->nexthash)
				old->nexthash->pprevhash=old->pprevhash;
			if (old->path) {
				if (node_hiddenpathcheck(old->fuse, old->path))
					ret_value = old->path;
				else
					free(old->path);
			}
			free(old);
    }
  }
  pthread_mutex_unlock(&node_mutex);
	return ret_value;
}

char *node_rename(struct fuse *fuse, const char *path, const char *newpath) {
	long hashsum = vnode_hash_sum(fuse, path);
  int hashkey = vnode_hash_mod(hashsum);
  struct fuse_node *this;
  char *ret_value = NULL;
  pthread_mutex_lock(&node_mutex);
	this = node_find(fuse, path, hashsum, hashkey);
	if (this != NULL) {
		*(this->pprevhash)=this->nexthash;
		if (this->nexthash)
			this->nexthash->pprevhash=this->pprevhash;
		if (this->path)
			free(this->path);
		if (newpath == NULL)
			this->path = node_hiddenpath(fuse);
		else
			this->path = strdup(newpath);
		hashsum = vnode_hash_sum(fuse, this->path);
		this->hashsum = hashsum;
		if (node_head[hashkey] != NULL)
			node_head[hashkey]->pprevhash = &(this->nexthash);
		this->nexthash = node_head[hashkey];
		this->pprevhash = &(node_head[hashkey]);
		node_head[hashkey] = this;
		ret_value = this->path;
	}
  pthread_mutex_unlock(&node_mutex);
	return ret_value;
}
