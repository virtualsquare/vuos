/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
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

#include <vumodule.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vufuse.h>
#include <vufuse_startmain.h>
#include <vufuse_default_ops.h>

VU_PROTOTYPES(vufuse)

struct vu_module_t vu_module = {
	.name = "vufuse",
	.description = "vu virtual file systems (user level FUSE)"
};

/* values for INUSE and thread synchro */
#define WAITING_FOR_LOOP -1
#define EXITING -2
#define FUSE_ABORT -3
static pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;

struct fusethreadopt {
	struct vuht_entry_t *ht;
	struct fuse_context *new_fuse;
	struct main_params main_params;
};

int vufuse_abort(struct fuse *f)
{
  f->inuse = FUSE_ABORT;
  pthread_mutex_lock( &condition_mutex );
  pthread_cond_signal( &f->startloop );
  pthread_mutex_unlock( &condition_mutex );

  return 0;
}

static void *fusethread(void *vsmo) {
	struct fusethreadopt *psmo = (struct fusethreadopt *) vsmo;
	vu_mod_setht(psmo->ht);

	if (fusestartmain(&psmo->main_params) != 0)
		vufuse_abort(psmo->new_fuse);

	pthread_exit(NULL);
  return NULL;
}

int vu_vufuse_mount(const char *source, const char *target, const char *filesystemtype,
   unsigned long mountflags, const void *data) {

	void *dlhandle = vu_mod_dlopen(filesystemtype, RTLD_NOW);
	int (*pmain)(int argc, char **argv, char** env);
#pragma GCC diagnostic ignored "-Wpedantic"
	if(dlhandle == NULL ||
			(pmain = dlsym(dlhandle,"main")) == NULL) {
#pragma GCC diagnostic warning "-Wpedantic"
		printk(KERN_ERR "%s",dlerror());
		if (dlhandle != NULL) dlclose(dlhandle);
		errno = ENOSYS;
		return -1;
	} else {
		struct fusethreadopt smo;
		struct vu_service_t *s = vu_mod_getservice();
		struct fuse_context *new;
		struct fuse *new_fuse;
		struct vuht_entry_t *ht;
		new = (struct fuse_context *) malloc(sizeof(struct fuse_context));
		if (new == NULL) goto err_nomem_new;
		new_fuse = new->fuse = (struct fuse *)malloc(sizeof(struct fuse));
		if (new_fuse == NULL) goto err_nomem_fuse;
		new_fuse->dlhandle = dlhandle;
		new_fuse->fops = vufuse_default_ops;
		new_fuse->flags = mountflags;
		new_fuse->inuse = WAITING_FOR_LOOP;

		/* XXX mumble on this */
		new->uid = geteuid();
    new->gid = getegid();
    new->pid = vu_mod_gettid();
    new->umask = vu_mod_getumask();
    new->private_data = NULL;

		ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, new);
		vu_mod_setht(ht);

		smo.ht = ht;
		smo.new_fuse = new_fuse;
		smo.main_params.pmain = pmain;
		smo.main_params.filesystemtype = filesystemtype;
		smo.main_params.source = source;
		smo.main_params.pflags = &(new_fuse->flags);
		smo.main_params.opts = (char *) data;

		pthread_cond_init(&(new_fuse->startloop),NULL);
    pthread_cond_init(&(new_fuse->endloop),NULL);
		pthread_create(&(new_fuse->thread), NULL, fusethread, (void *)&smo);

		printkdebug(F, "MOUNT source:%s target:%s filesystemtype:%s mountflags:%x data:%s",
				source,target,filesystemtype,mountflags, (data!=NULL)?data:"<NULL>");

		return 0;
err_nomem_fuse:
		free(new);
err_nomem_new:
		errno = ENOMEM;
		return -1;
	}
}

static void vufuse_umount_internal(struct fuse_context *fc) {
	pthread_mutex_lock( &condition_mutex );

	if (fc->fuse->fops.destroy != NULL )
      fc->fuse->fops.destroy(fc->private_data);

	pthread_cond_signal(&fc->fuse->endloop);
  pthread_mutex_unlock( &condition_mutex );
  pthread_join(fc->fuse->thread, NULL);

	dlclose(fc->fuse->dlhandle);
	free(fc->fuse);
  free(fc);
}

int vu_vufuse_umount2(const char *target, int flags) {
	struct fuse_context *fc=vu_get_ht_private_data();

  if (fc == NULL) {
		errno = EINVAL;
		return -1;
	} else if (fc->fuse->inuse) {
		errno = EBUSY;
		return -1;
	} else {
    /*cleanup and umount_internal will do the right umounting sequence in a lazy way*/
    vuht_del(vu_mod_getht(),flags);

    printkdebug(F,"UMOUNT target:%s flags:%d",target,flags);
    return 0;
  }
}

void vu_vufuse_cleanup(uint8_t type, void *arg, int arglen,struct vuht_entry_t *ht) {
  if (type == CHECKPATH) {
    struct fuse_context *fc = vuht_get_private_data(ht);
    if (fc == NULL) {
			errno = EINVAL;
		} else
			vufuse_umount_internal(fc);
  }
}

/*******************************************************************************************/
/* fuse related functions*/

int fuse_version(void) { return VUFUSE_FUSE_VERSION;}

struct fuse_context *fuse_get_context(void)
{

  struct fuse_context *context=(struct fuse_context *)vu_get_ht_private_data();
	/* uid gid ? get fs uid/gid? */
  context->pid=vu_mod_gettid();
  return context;
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
    size_t op_size, void *user_data)
{
  struct fuse *f;
  struct fuse_chan *fuseargs = fuse_mount(NULL, NULL); /*options have been already parsed*/
  f = fuse_new(fuseargs, NULL, op, op_size, user_data);

  return fuse_loop(f);
}

/* fuse_mount and fuse_unmount are dummy functions,
 * the real mount operation has been done in umfuse_mount */
struct fuse_chan *fuse_mount(const char *mountpoint, struct fuse_args *args)
{
  return (struct fuse_chan *) fuse_get_context();
}


void fuse_unmount(const char *mountpoint, struct fuse_chan *ch)
{
  return;
}

/* mergefun: set non-null functions */
typedef long (*sysfun)();
static void fopsmerge (struct fuse_operations *fops, const struct fuse_operations *modfops, size_t size)
{
  sysfun *f=(sysfun *)fops;
  sysfun *modf=(sysfun *) &modfops;
	size_t i;
	if (size > sizeof(struct fuse_operations))
		size = sizeof(struct fuse_operations);
	size /= sizeof(sysfun);
	for (i = 0; i < size; i++) {
		if (modf[i] != NULL)
			f[i] = modf[i];
	}
}

struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
    const struct fuse_operations *op, size_t op_size,
    void *user_data)
{
  struct fuse_context *fc=(struct fuse_context *)ch;
  if (op_size != sizeof(struct fuse_operations))
    printk("Fuse module vs vufuse support version mismatch");
  if (fc != fuse_get_context() || op_size != sizeof(struct fuse_operations)){
    fc->fuse->inuse=FUSE_ABORT;
    return NULL;
  }
  else {
    fc->private_data = user_data;
    fopsmerge(&fc->fuse->fops, op, op_size);
    return fc->fuse;
  }
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(F, "VUFUSE");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(F, "");
	}
