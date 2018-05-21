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

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<libgen.h>
#include<getopt.h>
#include<vulib.h>

static char *short_options = "h";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

void usage(char *argv0)
{
  char *name=basename(argv0);
  fprintf(stderr,
      "Usage: %s [options] stack cmd [args]\n",
			name);

	exit(1);
}

int main(int argc, char *argv[])
{
	int c;
	
	if (vu_getinfo(NULL) < 0) {
		fprintf(stderr, "vustack is a vuos command\n");
		return 1;
	}
	
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	if (argc > optind + 1) {
		char *stack = argv[optind];
		char *cmd = argv[optind + 1];
		char *newargv = argv + optind + 1;
		
		if (msocket(stack, 0, SOCK_DEFAULT, 0) < 0) {
			perror("vustack: msocket");
			exit(1);
		}

		execvp(cmd, newargv);
	} else
		usage(argv[0]);
	return 1;
}
