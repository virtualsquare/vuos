/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   with contributions by Alessio Volpe <alessio.volpe3@studio.unibo.it>
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
 *   Time virtualization:
 *   e.g.
 *      vu_insmod vumisc
 *      vumount -t vumisctime none /tmp/mnt
 *      ls /tmp/mount
 *      base  frequency  offset
 *
 *   if t is the time "below" this virtualization
 *   processes will se the time T
 *   T = (t - base) * freq + base + offset
 *
 *   base, frequency and offset can be changed by writing the "files"
 *   at the mountpoint (/tmp/mnt in the example)
 *   when frequency is changed, the new base is the "time below" atthe time of change
 *   and offset is changed to preserve continuity.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <vumisc.h>
#include <vumodule.h>

VUMISC_PROTOTYPES(vumisctime)

	struct vumisctime_t {
		long double offset;
		long double base;
		double freq;
	};

static struct vumisc_info infotree[] = {
	{"/", {.st_mode =  S_IFDIR | 0777}, ""},
	{"/frequency", {.st_mode =  S_IFREG | 0666}, "f"},
	{"/offset", {.st_mode =  S_IFREG | 0666}, "o"},
	{"/base", {.st_mode =  S_IFREG | 0666}, "b"},
	{NULL, {.st_mode = 0}, NULL}};


static long double get_virttime(struct vumisctime_t *vumisct)
{
	struct timespec ts;
	long double now;
	clock_gettime(CLOCK_REALTIME,&ts);
	now = ts.tv_sec + ((long double) ts.tv_nsec) / 1000000000;
	//printk("get_virttime now %Lf\n",now);
	now = (now - vumisct->base) * vumisct->freq + vumisct->base + vumisct->offset;
	//printk("get_virttime umnow %Lf\n",now);
	return now;
}

static void set_virttime(struct vumisctime_t *vumisct,long double newnow)
{
	long double now = get_virttime(vumisct);
	vumisct->offset += newnow - now;
}

static void set_newfreq(struct vumisctime_t *vumisct,long double newfreq)
{
	struct timespec ts;
	long double now;
	long double oldnow;
	long double newnow;
	clock_gettime(CLOCK_REALTIME,&ts);
	now = ts.tv_sec + ((long double) ts.tv_nsec) / 1000000000;
	oldnow = (now - vumisct->base) * vumisct->freq + vumisct->base;
	vumisct->base = now;
	vumisct->freq = newfreq;
	newnow = (now - vumisct->base) * vumisct->freq + vumisct->base;
	vumisct->offset += oldnow - newnow;
}

int infocontents(int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vumisctime_t *vumisctime_data = vumisc_get_private_data();
	char *filetag = pseudoprivate;
	if (tag == PSEUDOFILE_LOAD_CONTENTS) {
		switch (filetag[0]) {
			case 'f':
				fprintf(f, "%lf\n", vumisctime_data->freq);
				break;
			case 'o':
				fprintf(f, "%Lf\n", vumisctime_data->offset);
				break;
			case 'b':
				fprintf(f, "%Lf\n", vumisctime_data->base);
				break;
		}
	}
	if (tag == PSEUDOFILE_STORE_CLOSE &&
			(openflags & O_ACCMODE) != O_RDONLY	&& f != NULL) {
		switch (filetag[0]) {
			case 'f':
				{
					double newfreq;
					fscanf(f, "%lf\n", &newfreq);
					set_newfreq(vumisctime_data, newfreq);
				}
				break;
			case 'o':
				fscanf(f, "%Lf\n", &vumisctime_data->offset);
				break;
			case 'b':
				fscanf(f, "%Lf\n", &vumisctime_data->base);
				break;
		}
	}
	return 0;
}

int vumisctime_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	struct vumisctime_t *vumisctime_data = vumisc_get_private_data();
	if (clk_id == CLOCK_REALTIME) {
		if (tp) {
			long double now=get_virttime(vumisctime_data);
			tp->tv_sec = (time_t) now;
			tp->tv_nsec = (time_t) ((now - tp->tv_sec) * 1000000000);
		}
		return 0;
	}
	else
		return errno = ENOTSUP, -1;
}

int vumisctime_clock_settime(clockid_t clk_id, const struct timespec *tp) {
	struct vumisctime_t *vumisctime_data = vumisc_get_private_data();
	if (clk_id == CLOCK_REALTIME) {
		if (tp) {
			long double newnow;
			newnow = tp->tv_sec + ((long double) tp->tv_nsec) / 1000000000;
			set_virttime(vumisctime_data, newnow);
		}
		return 0;
	} else
		return errno = ENOTSUP, -1;
}

static void *vumisctime_init(const char *source) {
	struct vumisctime_t *new = malloc(sizeof(struct vumisctime_t));
	if (new) {
		new->freq = 1.0;
		new->offset = 0.0;
		new->base = 0.0;
	}
	return new;
}

static int vumisctime_fini(void *private) {
	free(private);
	return 0;
}

struct vumisc_operations_t vumisc_ops = {
	.infotree = infotree,
	.infocontents = infocontents,
	.init = vumisctime_init,
	.fini = vumisctime_fini,
};

