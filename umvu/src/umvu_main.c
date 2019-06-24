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
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <config.h>
#include <r_table.h>
#include <vu_log.h>
#include <vu_name.h>
#include <vu_nesting.h>
#include <vu_execute.h>
#include <vu_initfini.h>
#include <umvu_tracer.h>

static char *progname;
static char *short_options = "+hxNSl:s:f:V:o:d:D:";
static struct option long_options[] = {
	{"help",no_argument, 0, 'h'},
	{"nonesting",no_argument, 0, 'x'},
	{"rc",required_argument, 0, 'f'},
	{"norc",no_argument, 0, 'N'},
	{"output", required_argument, 0, 'o'},
	{"loglevel",required_argument, 0, 'l'},
	{"syslog",required_argument, 0, 's'},
	{"vu_name",required_argument,0,'V'},
	{"debugtags",required_argument,0,'d'},
	{"debugcols",required_argument,0,'D'},
	{"noseccomp",no_argument,0,'S'},
	{0,0,0,0}};

static void usage_n_exit(void) {
	fprintf(stderr,
			"UMVU: user mode implementation of VU-OS\n"
			"Copyright 2017-2018 VirtualSquare Team\n\n"
			"Usage:\n"
			"  %s OPTIONS cmd args\n\n"
			"    -h --help            print this short usage message\n"
			"    -x --nonesting       disable nested virtualization support\n"
			"    -f file\n"
			"       --rc file         set initialization file\n"
			"    -n --norc            do not load standard inizialization files\n"
			"    -l --loglevel        set log level (*)\n"
			"    -s --syslog          set syslog level (*)\n"
			"    -V name\n"
			"       --vu_name name    define the view name (see vuname)\n"
			"    -o outfile\n"
			"       --output outfile  redirect console output to outfile\n"
			"    -d tags\n"
			"       --debugtags tags  define the active debug tags (see vudebug)\n"
			"    -D cols\n"
			"       --debugcols cols  define the debug color string (see vudebug)\n"
			"    -S --noseccomp      disable_seccomp_optimization\n"
			"\n"
			"(*) 0:emerg 1:alert 2:crit 3:err 4-warning 5:notice 6:info 7:debug\n"
			"\n"
			, progname);
	r_exit(1);
}

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
	if (nesting)
		vu_nesting_init(argc, argv);
}

static void runrc(const char *path)
{
  if (faccessat(AT_FDCWD, path, X_OK, AT_EACCESS)==0) {
    int pid;
    int status;

    switch (pid=fork()) {
      case -1: exit(2);
      case 0: execl(path,path,(char *)0);
              exit(2);
			default: r_wait4(pid, &status, 0, NULL);
               if (!WIFEXITED(status))
                 exit(2);
    }
  }
}

int main(int argc, char *argv[])
{
	int c;
	int norc = 0;
	int seccomp = 1;
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
			case 'N': norc = 1;
								break;
			case 'S': seccomp = 0;
								break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if (vu_name)
		set_vu_name(vu_name);

	if (output_file) {
		set_log_file(output_file);
	}

	if (seccomp && umvu_tracer_test_seccomp() < 0) {
		printk(KERN_WARNING "seccomp_filter unavailable, use legacy ptrace instead\n");
		seccomp = 0;
	}

	childpid = umvu_tracer_fork(seccomp);

	if (childpid < 0)
		exit(1);
	else if (childpid > 0) {
		/* parent = tracer */
		int wstatus;
		vu_nesting_enable();
		vu_init();
		wstatus = umvu_tracepid(childpid, vu_syscall_execute, 1);
		vu_fini();
		r_exit(WEXITSTATUS(wstatus));
	} else {
		/* child: this is the root of all the traced processes */

		/* disable purelibc */
		vu_nesting_disable();

		/* run rcfile or default rc files: .vurc in home dir and /etc/vurc */
		if (rcfile)
			runrc(rcfile);
		else if (norc == 0) {
			char *home = getenv("HOME");
			runrc(ETC_VURC);
			if (home != NULL) {
				int homerc_len = strlen(home) + strlen(VURC) + 3;
				char homerc[homerc_len];
				snprintf(homerc, homerc_len, "%s/.%s", getenv("HOME"), VURC);
				runrc(homerc);
			}
		}

		execvp(argv[0], argv);
		return 1;
	}
}
