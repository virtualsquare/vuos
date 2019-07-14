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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <strcase.h>
#include <stropt.h>
#include <execs.h>
#include <vumodule.h>
#include <vufuse.h>
#include <vufuse_startmain.h>

#define FUSE_MOUNTFLAGS (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SYNCHRONOUS | MS_REMOUNT | \
		MS_MANDLOCK | MS_DIRSYNC | MS_NOATIME | MS_NODIRATIME | MS_POSIXACL | MS_RELATIME | MS_STRICTATIME | \
		MS_LAZYTIME)

static int countflagoptions(unsigned long mountflags) {
  int retval = 0;
  int i;
  for (i = 0; i < 32; i++) {
    if ((mountflags & (1UL << i)) && (mountflag_strings[i]))
      retval++;
  }
  return retval;
}

static void addflagoptions(char **tags, char **args, unsigned long mountflags) {
  int i;
  int flagoptc;
  for (i = 0, flagoptc = 0; i < 32; i++) {
    if ((mountflags & (1UL << i)) && (mountflag_strings[i])) {
      tags[flagoptc] = mountflag_strings[i];
      args[flagoptc] = NULL;
      flagoptc++;
    }
  }
  tags[flagoptc] = NULL;
  args[flagoptc] = NULL;
}

int fusestartmain(struct main_params *mntp) {
	int tagc = stropt(mntp->opts, NULL, NULL, 0) - 1;
	int flagtagc =  countflagoptions(*mntp->pmountflags & FUSE_MOUNTFLAGS);
	char buf[strlen(mntp->opts)+1];
	char *newopts = NULL;
	char *format = "%N -o %O %S %T";
	int i;
	int retval;

#define copy_mntp_on_stack(string) \
	size_t string ## _len = strlen(mntp->string) + 1;	\
	char string[string ## _len]; \
	strncpy(string, mntp->string, string ## _len)

	copy_mntp_on_stack(filesystemtype);
	copy_mntp_on_stack(source);
	copy_mntp_on_stack(target);
	if(tagc + flagtagc == 0)
		newopts = strdup("rw");
	else {
		int tags_args_len = tagc + flagtagc + 1;
		char *tags[tags_args_len];
		char *args[tags_args_len];
		stropt(mntp->opts, tags, args, buf);
		for (i = 0; i < tagc; i++) {
			//printf("%s =%s\n",tags[i],args[i]);
			switch(strcase(tags[i])) {
				case STRCASE(f,m,t): format = args[i]; tags[i] = STROPTX_DELETED_TAG; break;
														 /* here some opt could change bits in mntp->pfuseflags */
				case STRCASE(h,a,r,d,_,r,e,m,o,v,e): *mntp->pfuseflags |= FUSE_HARDREMOVE;
																						 tags[i] = STROPTX_DELETED_TAG; break;
			}
		}
		addflagoptions(tags+tagc, args+tagc, *mntp->pmountflags & FUSE_MOUNTFLAGS);
		newopts = stropt2str(tags, args, ',', '=');
	}
	//printf("NEWOPTS = %s\n", newopts);
	//printf("FORMAT = %s\n", format);
	char **xargv = s2argv(format);
	int xargc = s2argc(xargv);
	char *argv[xargc + 2];
	int argc = 0;
	for (i = 0; i < xargc; i++) {
		switch(strcase(xargv[i])) {
			case STRCASE(perc,N):
				argv[argc++] = filesystemtype; break;
			case STRCASE(perc,O):
				argv[argc++] = newopts; break;
			case STRCASE(perc,S):
				argv[argc++] = source; break;
			case STRCASE(perc,T):
				argv[argc++] = target; break;
			default: argv[argc++] = xargv[i];
		}
	}
	argv[argc] = NULL;
#if 0
	printf("ARG %s\n", mntp->opts);
	printf("argc %d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("%i %s\n",i,argv[i]);
	}
#endif
	optind = 1;
	retval = mntp->pmain(argc, argv);
	s2argv_free(xargv);
	free(newopts);
	return retval;
}
