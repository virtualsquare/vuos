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
 *   UMDEV: Virtual Device in Userspace
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#include <r_table.h>
#include <vu_log.h>
#include <vu_name.h>
#include <vu_nesting.h>
#include <vu_execute.h>
#include <vu_initfini.h>
#include <umvu_tracer.h>

static char *progname;
static char *short_options = "+hxl:s:f:V:o:d:D:";
static struct option long_options[] = {
	{"help",no_argument, 0, 'h'},
	{"nonesting",no_argument, 0, 'x'},
	{"rc",required_argument, 0, 'f'},
	{"output", required_argument, 0, 'o'},
	{"loglevel",required_argument, 0, 'l'},
	{"syslog",required_argument, 0, 's'},
	{"vu_name",required_argument,0,'V'},
	{"debugtags",required_argument,0,'d'},
	{"debugcols",required_argument,0,'D'},
	{0,0,0,0}};

static void usage_n_exit(void) {
	fprintf(stderr, 
			"UMVU: user mode implementation of VU-OS\n"
			"Copyright 2017 VirtualSquare Team\n\n"
			"Usage:\n"
			"\t%s OPTIONS cmd args\n\n"
			"\t\t-h --help      print this short usage message\n"
			"\t\t-x --nonesting disable nested virtualization support\n"  // umvu +x works, umvu -x doesn't work
			"\t\t-f file\n"
			"\t\t   --rc file   initialization file\n"
			/* XXX to be completed */
			, progname);
	exit(1);
}

/**Early arguments are pre-managed.*/
static void early_args(int argc, char *argv[]) {
	int c;
	int nesting __attribute__((unused)) = 1;
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case '?':
			case 'h': usage_n_exit();
								break;
			case 'x': nesting = 0;
								break;
		}
	}
	/**Enabling nested virtualization via purelibc, eventually re-executing umvu.*/
	if (nesting)
		vu_nesting_init(argc, argv);

}

int main(int argc, char *argv[])
{
	int c;
	char *output_file = NULL;
	char *rcfile = NULL;
	char *vu_name = NULL;
	int childpid;
	progname = basename(argv[0]);
	early_args(argc, argv);
	
    
	/* rewind args */
	optind = 1;
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		
		if (c == -1)
			break;

		switch (c) {
			case '?': usage_n_exit();
								break;
			case 'd': debug_add_tags(optarg, 0);
								break;
			case 'D': debug_set_color_string(optarg);
								break;	
			case 'l': set_console_log_level(atoi(optarg));
								break;
			case 's': set_syslog_log_level(atoi(optarg));
								break;
			case 'o': output_file = optarg;
								break;
			case 'f': rcfile = optarg;
								break;
			case 'V': vu_name = optarg;
								break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if (vu_name)
		set_vu_name(vu_name);

	if (output_file) {
		/* XXX divert output, debug output only or everything? */
	}
	if ((childpid = umvu_tracer_fork()) != 0) {
		/* parent = tracer */
		int wstatus;
		vu_init();
		wstatus = umvu_tracepid(childpid, vu_syscall_execute, 1);
		vu_fini();
		r_exit(WEXITSTATUS(wstatus));
	} else {
		/* child: this is the root of all the traced processes */
		/** disable purelibc. */
		unsetenv("LD_PRELOAD");
		/* XXX run rc file files: .vurc in home dir and /etc/vurc */
		if (rcfile) {
		}

	 
		
		execvp(argv[0], argv);
		return 1;
	}
}
