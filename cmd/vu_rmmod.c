/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <vulib.h>

static char *progname;
void usage()
{
  fprintf(stderr,
			"Usage:\n"
			"  %s OPTIONS vu_module [vu_module] ...\n"
			"  OPTIONS:\n"
			"    -h --help:  print this help message\n\n", progname);
  exit(2);
}

static const char *short_options = "p";
static const struct option long_options[] = {
	{"help",0,0,'h'},
	{0,0,0,0}
};

int main(int argc, char *argv[])
{
  int c;
	progname = basename(argv[0]);
  if (vu_check() < 0) {
    fprintf(stderr,"This is a VUOS command."
				"It works only inside a vuos virtual namespace\n");
    usage();
  }
  while (1) {
    c=getopt_long(argc, argv,
				short_options, long_options, NULL);
    if (c == -1) break;
    switch (c) {
      case 'h': usage();
                break;
    }
  }
  if (argc - optind < 1)
    usage();
  else {
    int rv=0;
    int i;
    for (i = optind; i < argc; i++) {
      if (vu_rmmod(argv[i]) < 0) {
        perror(argv[i]);
        rv=1;
      }
    }
    return rv;
  }
  return 0;
}
