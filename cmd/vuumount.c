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

void usage(char *argv0)
{
	char *name=basename(argv0);
	fprintf(stderr,
			"Usage:\n"
			" %s [options] <target>\n\n"
			"Unmount a filesystem.\n\n"
			"Options:\n"
			" -f, --force             force unmount (in case of an unreachable NFS system)\n"
			" -d, --detach-loop       if mounted loop device, also free this loop device\n"
			" -h, --help              display this help\n"
			"\n",
			name);

	exit(1);
}

int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *target = NULL;
	int flags = 0;

	int c;
	static char *short_options = "hfd";
	static struct option long_options[] = {
		{"force", no_argument, 0, 'f'},
		{"detach-loop", no_argument, 0, 'd'},
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
			case 'f':
				flags |= MNT_FORCE;
				break;
			case 'd':
				flags |= MNT_DETACH;
				break;
			case 'h':
			default:
				usage(progname);
				break;
		}
	}
	if ((optind + 1) != argc)
		usage(progname); // this implies exit

	target = argv[optind];

	if (umount2(target, flags) < 0)
		perror(progname);
	return 0;
}
