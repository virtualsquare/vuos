/*
 *   VUOS: view OS project
 *   Copyright (C) 2019  Renzo Davoli <renzo@cs.unibo.it>
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

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<getopt.h>
#include<sys/mount.h>
#include<stropt.h>

#define DEFAULT_FILESYSTEMTYPE ""
#define DEFAULT_MOUNTFLAGS (MS_SILENT)
static char default_options[] = "defaults";

struct mountopts_t {
	char *opt;
	unsigned long mountflags_on;
	unsigned long mountflags_off;
};

struct mountopts_t mountopts[] = {
	{"defaults", 0, 0},
	{"user", MS_NOSUID | MS_NODEV | MS_NOEXEC, 0},
	{"group", MS_NOSUID | MS_NODEV, 0},
	{"ro", MS_RDONLY, 0},
	{"rw", 0, MS_RDONLY},
	{"suid", 0, MS_NOSUID},
	{"nosuid", MS_NOSUID, 0},
	{"dev", 0, MS_NODEV},
	{"nodev", MS_NODEV, 0},
	{"exec", 0, MS_NOEXEC},
	{"noexec", MS_NOEXEC, 0},
	{"async", 0, MS_SYNCHRONOUS},
	{"sync", MS_SYNCHRONOUS, 0},
	{"remount", MS_REMOUNT, 0},
	{"mand", MS_MANDLOCK, 0},
	{"nomand", 0, MS_MANDLOCK},
	{"dirsync", MS_DIRSYNC, 0},
	{"atime", 0, MS_NOATIME},
	{"noatime", MS_NOATIME, 0},
	{"diratime", 0, MS_NODIRATIME},
	{"nodiratime", MS_NODIRATIME, 0},
	{"bind", MS_BIND, 0},
	{"move", MS_MOVE, 0},
	{"rbind", MS_BIND | MS_REC, 0},
	{"silent", MS_SILENT, 0},
	{"loud", 0, MS_SILENT},
	{"acl", MS_POSIXACL, 0},
	{"realtime", MS_RELATIME, 0},
	{"norealtime", 0, MS_RELATIME},
	{"iversion", MS_I_VERSION, 0},
	{"noiversion", 0, MS_I_VERSION},
	{"strictatime", MS_STRICTATIME, 0},
	{"nostrictatime", 0, MS_STRICTATIME},
	{"lazytime", MS_LAZYTIME, 0},
	{"nolazytime", 0, MS_LAZYTIME},
};

#define NMO (int)(sizeof(mountopts) / sizeof(*mountopts))

int opt2flag(const char *mountopt, unsigned long *mountflags) {
	int i;
	for (i = 0; i < NMO; i++) {
		if (strcmp(mountopt, mountopts[i].opt) == 0) {
			*mountflags &= ~mountopts[i].mountflags_off;
			*mountflags |= mountopts[i].mountflags_on;
			return 1;
		}
	}
	return 0;
}

void usage(char *argv0)
{
	char *name=basename(argv0);
	fprintf(stderr,
			"Usage:\n"
			" %s [options] <source> <directory>\n\n"
			"Mount a filesystem.\n\n"
			"Options:\n"
			" -o, --options <list>    comma-separated list of mount options\n"
			" -t, --types <list>      limit the set of filesystem types\n"
			" -r, --read-only         mount the filesystem read-only (same as -o ro)\n"
			" -w, --rw, --read-write  mount the filesystem read-write (default)\n"
			" -B, --bind              mount a subtree somewhere else (same as -o bind)\n"
			" -M, --move              move a subtree to some other place\n"
			" -R, --rbind             mount a subtree and all submounts somewhere else\n"
			" -h, --help              display this help\n"
			"\n",
			name);

	exit(1);
}

char *parse_options(char *options, unsigned long *mountflags) {
	int tagc = stropt(options, NULL, NULL, 0);
	if(tagc > 0) {
		char *tags[tagc];
		char *args[tagc];
		stropt(options, tags, args, options);
		for (int i=0; i < tagc; i++) {
			if (args[i] == NULL && tags[i] != NULL &&
					opt2flag(tags[i], mountflags) > 0)
				tags[i] = STROPTX_DELETED_TAG;
		}
		return stropt2str(tags, args, ',', '=');
  } else
		return options;
}


int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *source = NULL;
	char *target = NULL;
	char *filesystemtype = DEFAULT_FILESYSTEMTYPE;
	char *options = default_options;
	unsigned long mountflags = DEFAULT_MOUNTFLAGS;

	int c;
	static char *short_options = "ht:o:rwBMR";
	static struct option long_options[] = {
		{"types", required_argument, 0, 't'},
		{"options", required_argument, 0, 'o'},
		{"read-only", no_argument, 0, 'r'},
		{"read-write", no_argument, 0, 'w'},
		{"rw", no_argument, 0, 'w'},
		{"bind", no_argument, 0, 'B'},
		{"move", no_argument, 0, 'M'},
		{"rbind", no_argument, 0, 'R'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 't':
				filesystemtype = optarg;
				break;
			case 'o':
				options = optarg;
				break;
			case 'r':
				opt2flag("ro", &mountflags);
				break;
			case 'w':
				opt2flag("rw", &mountflags);
				break;
			case 'B':
				opt2flag("bind", &mountflags);
				break;
			case 'M':
				opt2flag("move", &mountflags);
				break;
			case 'R':
				opt2flag("rbind", &mountflags);
				break;
			case 'h':
			default:
				usage(progname);
				break;
		}
	}
	if ((optind + 2) != argc)
		usage(progname); // this implies exit

	source = argv[optind];
	target = argv[optind + 1];

	options = parse_options(options, &mountflags);

	if (mount(source, target, filesystemtype, mountflags, options) < 0)
		perror(progname);
	return 0;
}
