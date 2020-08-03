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
	struct fuse *new_fuse;
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

	if (fusestartmain(&psmo->main_params) != 0)
		vufuse_abort(psmo->new_fuse);

	pthread_exit(NULL);
	return NULL;
}

int vu_vufuse_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {

	void *dlhandle = vu_mod_dlopen(filesystemtype, RTLD_NOW);
	int (*pmain)(int argc, char **argv);

	//printk("vu_vufuse_mount %s %s %s 0x%x %s\n", source, target, filesystemtype, mountflags, data);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	if(dlhandle == NULL ||
			(pmain = dlsym(dlhandle,"main")) == NULL) {
#pragma GCC diagnostic pop
		if (dlhandle != NULL) {
			printk(KERN_ERR "%s",dlerror());
			dlclose(dlhandle);
		}
		errno = ENOSYS;
		return -1;
	} else {
		struct fusethreadopt smo;
		struct vu_service_t *s = vu_mod_getservice();
		struct fuse *new_fuse;
		struct vuht_entry_t *ht;
		new_fuse = (struct fuse *)malloc(sizeof(struct fuse));
		if (new_fuse == NULL)
			goto err_nomem_fuse;
		new_fuse->dlhandle = dlhandle;
		new_fuse->fops = vufuse_default_ops;
		new_fuse->mountflags = mountflags;
		new_fuse->fuseflags = 0;
		new_fuse->inuse = WAITING_FOR_LOOP;

		new_fuse->private_data = NULL;

		pthread_mutex_init(&(new_fuse->mutex), NULL);
		pthread_cond_init(&(new_fuse->startloop), NULL);
		pthread_cond_init(&(new_fuse->endloop), NULL);

		pthread_mutex_lock(&(new_fuse->mutex));

		ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, new_fuse);
		vu_mod_setht(ht);

		smo.new_fuse = new_fuse;
		smo.main_params.pmain = pmain;
		smo.main_params.filesystemtype = filesystemtype;
		smo.main_params.source = source;
		smo.main_params.target = target;
		smo.main_params.pmountflags = &(new_fuse->mountflags);
		smo.main_params.pfuseflags = &(new_fuse->fuseflags);
		smo.main_params.opts = data ? (char *) data : "";

		pthread_create(&(new_fuse->thread), NULL, fusethread, (void *)&smo);

		pthread_mutex_lock( &condition_mutex );
		if (new_fuse->inuse== WAITING_FOR_LOOP)
			pthread_cond_wait( &(new_fuse->startloop), &condition_mutex);
		pthread_mutex_unlock( &condition_mutex );

		if (new_fuse->inuse == FUSE_ABORT)
			goto err_startloop_fault;

		if (new_fuse->fops.init != NULL) {
			struct fuse_conn_info conn;
			struct fuse_context fcx, *ofcx;
			ofcx = fuse_push_context (&fcx);
			new_fuse->private_data=new_fuse->fops.init(&conn);
			fuse_pop_context(ofcx);
		}

		pthread_mutex_unlock(&(new_fuse->mutex));
		printkdebug(F, "MOUNT source:%s target:%s filesystemtype:%s mountflags:%x data:%s",
				source,target,filesystemtype,mountflags, (data!=NULL)?data:"<NULL>");

		return 0;
err_startloop_fault:
		pthread_mutex_unlock(&(new_fuse->mutex));
		/* new and new_fuse as well as waiting for the thread to terminate
			 done by cleanup */
		vuht_del(ht,1);
		errno = EFAULT; /* temporary solution */
		return -1;
err_nomem_fuse:
		dlclose(dlhandle);
		errno = ENOMEM;
		return -1;
	}
}

static void vufuse_umount_internal(struct fuse *fuse) {

	if (fuse->fops.destroy != NULL ) {
		struct fuse_context fcx, *ofcx;
		ofcx = fuse_push_context (&fcx);
		fuse->fops.destroy(fuse->private_data);
		fuse_pop_context(ofcx);
	}

	pthread_mutex_lock( &condition_mutex );
	fuse->inuse= EXITING;
	pthread_cond_signal(&fuse->endloop);
	pthread_mutex_unlock( &condition_mutex );
	pthread_join(fuse->thread, NULL);
	pthread_cond_destroy(&(fuse->startloop));
	pthread_cond_destroy(&(fuse->endloop));
	pthread_mutex_destroy(&(fuse->mutex));

	dlclose(fuse->dlhandle);
	free(fuse);
}

int vu_vufuse_umount2(const char *target, int flags) {
	struct fuse *fuse = vu_get_ht_private_data();

	if (fuse == NULL) {
		errno = EINVAL;
		return -1;
	} else  {
		pthread_mutex_lock(&(fuse->mutex));
		if (fuse->inuse) {
			pthread_mutex_unlock(&(fuse->mutex));
			errno = EBUSY;
			return -1;
		} else {
			int retval;
			/*cleanup and umount_internal will do the right umounting sequence in a lazy way*/
			if ((retval = vuht_del(vu_mod_getht(),flags)) < 0) {;
				errno = -retval;
				retval = -1;
			}
			pthread_mutex_unlock(&(fuse->mutex));
			printkdebug(F,"UMOUNT target:%s flags:%d retval = %d",target,flags,retval);
			return retval;
		}
	}
}

void vu_vufuse_cleanup(uint8_t type, void *arg, int arglen,struct vuht_entry_t *ht) {
	if (type == CHECKPATH) {
		struct fuse *fuse = vuht_get_private_data(ht);
		if (fuse == NULL) {
			errno = EINVAL;
		} else
			vufuse_umount_internal(fuse);
	}
}

/* management of context */
static __thread struct fuse_context *__fuse_context;

struct fuse_context *fuse_push_context(struct fuse_context *new) {
	struct fuse_context *old_fuse_context = __fuse_context;
	struct fuse *fuse = vu_get_ht_private_data();
	new->uid = geteuid();
	new->gid = getegid();
	new->pid = vu_mod_gettid();
	new->umask = vu_mod_getumask();
	new->fuse = fuse;
	new->private_data = fuse->private_data;
	__fuse_context = new;
	return old_fuse_context;
}

void fuse_pop_context(struct fuse_context *old) {
	__fuse_context = old;
}

/*******************************************************************************************/
/* fuse related functions*/

int fuse_version(void) { return VUFUSE_FUSE_VERSION;}

struct fuse_context *fuse_get_context(void)
{
	return __fuse_context;
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		size_t op_size, void *user_data)
{
	struct fuse *f;
	struct fuse_chan *fusechan = fuse_mount(NULL, NULL); /*options have been already parsed*/
	if (fusechan != NULL) {
		f = fuse_new(fusechan, NULL, op, op_size, user_data);

		return fuse_loop(f);
	} else
		return -1;
}

/* fuse_mount and fuse_unmount are dummy functions,
 * the real mount operation has been done in vufuse_mount */
struct fuse_chan *fuse_mount(const char *mountpoint, struct fuse_args *args)
{
	return vu_get_ht_private_data();
}


void fuse_unmount(const char *mountpoint, struct fuse_chan *ch)
{
	return;
}

/* mergefun: set non-null functions */
static void fopsmerge (const struct fuse_operations *fops, const struct fuse_operations *modfops, size_t size)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	const void **f = fops;
	const void **modf = modfops;
#pragma GCC diagnostic pop
	size_t i;
	if (size > sizeof(struct fuse_operations))
		size = sizeof(struct fuse_operations);
	size = size / sizeof(void *);
	for (i = 0; i <size; i++) {
		if (modf[i] != NULL)
			f[i] = modf[i];
	}
}

struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
		const struct fuse_operations *op, size_t op_size,
		void *user_data)
{
	struct fuse *fuse = (struct fuse *)ch;
	if (op_size != sizeof(struct fuse_operations))
		printk(KERN_ERR "Fuse module vs vufuse support version mismatch");
	if (fuse != vu_get_ht_private_data() || op_size != sizeof(struct fuse_operations)){
		fuse->inuse=FUSE_ABORT;
		return NULL;
	}
	else {
		fuse->private_data = user_data;
		fopsmerge(&fuse->fops, op, op_size);
		return fuse;
	}
}

void fuse_destroy(struct fuse *f)
{
	/*  **
	 * Destroy the FUSE handle.
	 *
	 * The filesystem is not unmounted.
	 *
	 * @param f the FUSE handle
	 */
}

int fuse_loop(struct fuse *f)
{
	if (f != NULL) {

		pthread_mutex_lock( &condition_mutex );
		f->inuse = 0;
		pthread_cond_signal( &f->startloop );
		////pthread_mutex_unlock( &condition_mutex );
		//pthread_mutex_lock( &f->endmutex );
		////pthread_mutex_lock( &condition_mutex );
		if (f->inuse != EXITING) {
			//pthread_cond_wait( &f->endloop, &f->endmutex );
			pthread_cond_wait( &f->endloop, &condition_mutex );
		}
		//pthread_mutex_unlock( &f->endmutex );
		pthread_mutex_unlock( &condition_mutex );
	}
	return 0;
}


void fuse_exit(struct fuse *f)
{
	/**
	 * Exit from event loop
	 *
	 * @param f the FUSE handle
	 */

}

int fuse_loop_mt(struct fuse *f)
{
	//in fuselib is FUSE event loop with multiple threads,
	//but hereeverything has multiple threads ;-)
	return fuse_loop(f);
}



__attribute__((constructor))
	static void init(void) {
		debug_set_name(F, "VUFUSE");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(F, "");
	}
