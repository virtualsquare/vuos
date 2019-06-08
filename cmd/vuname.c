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
#include <string.h>
#include <vulib.h>

char *progname;
int quiet;
struct vu_info vi;

void version_exit(void) {
	printf("umviewname (VUOS project) 1.0\n"
			"Copyright (C) 2017 Virtualsquare Team\n"
			"This is free software.  You may redistribute copies of it under the terms of\n"
			"the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n"

			"Written by Renzo Davoli\n");
	exit(0);
}

void usage_exit(int exit_status)
{
	if (!quiet) {
		fprintf(stderr, 
				"Usage: vuname [OPTION]...\n"
				" Print certain VUOS system information.  With no OPTION, same as -s.\n"
				"Usage: vuname newname\n"
				" Set the VUOS view name\n"
				"\n"
				" -a, --all                print all information, in the following order,\n"
				" except omit -p and -i if unknown:\n"
				" -s, --kernel-name        print the kernel name\n"
				" -n, --nodename           print the network node hostname\n"
				" -r, --kernel-release     print the kernel release\n"
				" -v, --kernel-version     print the kernel version\n"
				" -m, --machine            print the machine hardware name\n"
				" -p, --processor          print the processor type or \"unknown\"\n"
				" -i, --hardware-platform  print the hardware platform or \"unknown\"\n"
				" -o, --operating-system   print the operating system\n"
				" -U, --serverid           print the server id\n"
				" -V, --viewname           print the view name\n"
				"other options\n"
				" -P, --prompt             print a string for user prompts\n"
				" -q, --quiet              quiet mode: silent on errors\n"
				" -x, --nouname            do not use uname when outside VUOS\n"
				"     --help     display this help and exit\n"
				"     --version  output version information and exit\n"
				"\n");
	}
	exit(exit_status);
}

static char short_options[] = "snrvmpioUVaxqPN";
static char field_options[] = "snrvmpioUV";
static char vuos_options[]  = "        vv";
static char unknown[] = "unknown";
static char vuos[] = "GNU/Linux/VUOS";
static char no_vuos[] = "GNU/Linux";
static char *fields[] = {
	/* s */ vi.uname.sysname,
	/* n */ vi.uname.nodename,
	/* r */ vi.uname.release,
	/* v */ vi.uname.version,
	/* m */ vi.uname.machine,
	/* p */ unknown,
	/* i */ unknown,
	/* o */ no_vuos,
	/* U */ vi.vu_serverid,
	/* V */ vi.vu_name
};

static struct option long_options[] = {
	{"all", 0, 0, 'a'},
	{"kernel-name", 0, 0, 's'},
	{"nodename",0,0,'n'},
	{"kernel-release",0,0,'r'},
	{"kernel-version",0,0,'v'},
	{"machine",0,0,'m'},
	{"processor",0,0,'p'},
	{"hardware-platform",0,0,'i'},
	{"operating-system",0,0,'o'},
	{"serverid",0,0,'U'},
	{"viewid",0,0,'V'},
	{"viewname",0,0,'N'},
	{"quiet",0,0,'q'},
	{"nouname",0,0,'x'},
	{"promt",0,0,'P'},
	{"help",0,0,0x100},
	{"version",0,0,0x101},
	{0,0,0,0}
};

static int ch2fieldindex(char c) {
	char *c_in_opt = strchr(field_options, c);
	return (c_in_opt == NULL) ? -1 : c_in_opt - field_options;
}

int main(int argc, char *argv[])
{
	int prompt = 0;
	int flags = 0;
	int kernel_uname = 1;
	int ret_value;
	progname = basename(argv[0]);
	while (1) {
		int c;
		c = getopt_long(argc, argv, short_options, long_options, NULL);
		if (c == -1) break;
		switch (c) {
			case 'a': flags = -1; break;
			case 'q': quiet = 1; break;
			case 'P': prompt = 1; break;
			case 'x': kernel_uname = 0; break;
			case 0x100:
								usage_exit(0);
								break;
			case 0x101:
								version_exit();
								break;
			case 'N' : c = 'V'; 
								 /* for backwards compatibility */
								 __attribute__ ((fallthrough));
			default: ret_value = ch2fieldindex(c);
							 if (ret_value >= 0) 
								 flags |= 1 << ret_value;
							 else
								 usage_exit(1);
							 break;
		}
	}
	if (argc - optind != 0) {
		/* with one argument and nooptions it sets the viewname */
		if (argc - optind == 1 && optind == 1) {
			if (vu_setname(argv[optind]) == 0)
				exit(0);
			else {
				if (!quiet) perror(progname);
				exit (1);
			}
		}
		usage_exit(1);
	}
	ret_value = vu_getinfo(&vi);
	if (ret_value < 0) {
		if (kernel_uname)
			ret_value = uname(&vi.uname);
		if (ret_value < 0) {
			if (!quiet) perror(progname);
			exit (1);
		}
	} else {
		fields[ch2fieldindex('o')] = vuos;
		kernel_uname = 0;
	}
	if (prompt) {
		if (kernel_uname) 
			printf("%s\n",vi.uname.nodename);
		else if (strlen(vi.vu_name) > 0)
			printf("%s\n",vi.vu_name);
		else
			printf("%s[%s]\n",vi.uname.nodename,vi.vu_serverid);
	} else if (flags == 0)
		printf("%s\n",vi.uname.sysname);
	else {
		unsigned int n;
		char *sep;
		for (n = 0, sep = ""; n < sizeof(field_options) - 1; n++) {
			if (flags & (1 << n) && 
					(kernel_uname == 0 || vuos_options[n] == ' ') &&
					(flags != -1 || fields[n] != unknown)) {
				printf("%s%s", sep, fields[n]);
				sep = " ";
			}
		}
		printf("\n");
	}
	return 0;
}
