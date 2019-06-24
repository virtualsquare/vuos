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
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stropt.h>
#include <strcase.h>
#include <vulib.h>

static char *progname;

/* This is the command that creates the list of proocol family names
echo "#include<sys/socket.h>" | gcc -E -dD - | egrep '^#define  *PF_.*[0-9]$' | \
awk 'BEGIN {printf "static char *pf_names[] = { \\\n"}   {printf "  [%s] = \"%s\", \\\n", $3, substr(tolower($2),4)} END {printf "};\n"}'
*/

static char *pf_names[] = { \
  [0] = "unspec", \
  [1] = "local", \
  [2] = "inet", \
  [3] = "ax25", \
  [4] = "ipx", \
  [5] = "appletalk", \
  [6] = "netrom", \
  [7] = "bridge", \
  [8] = "atmpvc", \
  [9] = "x25", \
  [10] = "inet6", \
  [11] = "rose", \
  [12] = "decnet", \
  [13] = "netbeui", \
  [14] = "security", \
  [15] = "key", \
  [16] = "netlink", \
  [17] = "packet", \
  [18] = "ash", \
  [19] = "econet", \
  [20] = "atmsvc", \
  [21] = "rds", \
  [22] = "sna", \
  [23] = "irda", \
  [24] = "pppox", \
  [25] = "wanpipe", \
  [26] = "llc", \
  [27] = "ib", \
  [28] = "mpls", \
  [29] = "can", \
  [30] = "tipc", \
  [31] = "bluetooth", \
  [32] = "iucv", \
  [33] = "rxrpc", \
  [34] = "isdn", \
  [35] = "phonet", \
  [36] = "ieee802154", \
  [37] = "caif", \
  [38] = "alg", \
  [39] = "nfc", \
  [40] = "vsock", \
  [41] = "kcm", \
  [42] = "qipcrtr", \
  [43] = "smc", \
  [44] = "max", \
};

#define PF_NAMES_SIZE ((int)(sizeof(pf_names) / sizeof(*pf_names)))
#define PF_EXTRA_SIZE (PF_NAMES_SIZE + 10)

static unsigned char vustack_proto[PF_EXTRA_SIZE] = { [PF_UNSPEC] = 1 };

static char *pf_num2nname(int family) {
	if (family >= 0 && family < PF_NAMES_SIZE - 1)
		return pf_names[family];
	else
		return "unknown";
}

static int pf_name2num(char *pf_name) {
	int family;
	for (family = 0; family < PF_NAMES_SIZE; family++)
		if (pf_names[family] != NULL && strcmp(pf_name, pf_names[family]) == 0)
			return family;
	return -1;
}

static int is_a_stack(char *stack) {
	struct stat buf;
	int rv = stat(stack, &buf);
	if (rv < 0)
		return rv;
	else if ((buf.st_mode & S_IFMT) != S_IFSTACK)
		return errno=ENOTSUP, -1;
	else
		return 0;
}

static void add_supported_families(char *stack) {
	int family;
	vustack_proto[PF_UNSPEC] = 0;
	for (family = 1; family < PF_EXTRA_SIZE; family++) {
		int fd = msocket(stack, family, -1, 0);
		if (fd >= 0 || errno == EINVAL)
				vustack_proto[family] = 1;
		if (fd >= 0)
			close(fd);
	}
}

static void process_families(const char *input) {
	int tagc = stropt(input, NULL, NULL, 0);
  if(tagc > 0) {
    char buf[strlen(input)+1];
    char *tags[tagc];
    stropt(input, tags, NULL, buf);
		vustack_proto[PF_UNSPEC] = 0;
    for (int i=0; i < tagc - 1; i++) {
			switch(strcase_tolower(tags[i])) {
				case STRCASE(i,p):
					vustack_proto[PF_INET] = 1;
					vustack_proto[PF_INET6] = 1;
					vustack_proto[PF_NETLINK] = 1;
					vustack_proto[PF_PACKET] = 1;
					break;
				case STRCASE(i,p,v,4):
				case STRCASE(i,p,4):
					vustack_proto[PF_INET] = 1;
					break;
				case STRCASE(i,p,v,6):
				case STRCASE(i,p,6):
					vustack_proto[PF_INET6] = 1;
					break;
				case STRCASE(b,t):
					vustack_proto[PF_BLUETOOTH] = 1;
					break;
				case STRCASE(i,r):
					vustack_proto[PF_IRDA] = 1;
					break;
				default:
					if (isdigit(tags[i][0])) {
						int family = strtol(tags[i], NULL, 0);
						if (family > 0 && family < PF_EXTRA_SIZE)
							vustack_proto[family] = 1;
						else {
							fprintf(stderr, "%s: unknown protocol family %s\n", progname, tags[i]);
							exit(1);
						}
					} else {
						int family = pf_name2num(tags[i]);
						if (family > 0)
							vustack_proto[family] = 1;
						else {
							fprintf(stderr, "%s: unknown protocol family %s\n", progname, tags[i]);
							exit(1);
						}
					}
			}
		}
  }
}

static char *short_options = "hvsf:";
static struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"verbose", no_argument, 0, 'v'},
	{"supported", no_argument, 0, 's'},
	{"family", required_argument, 0, 'f'},
	{"families", required_argument, 0, 'f'},
	{0, 0, 0, 0}
};

void usage(char *progname, int verbose)
{
  fprintf(stderr,
			"%s: set the default networking stack\n\n"
      "Usage: %s [options] stack cmd [args]\n\n"
			"    -h --help            print this short usage message\n"
			"    -f list\n"
			"      -family list\n"
			"      -families list     set the list of address families\n"
			"    -s --supported       all families supported by the stack\n\n"
			"    -v --verbose         verbose mode\n\n",
			progname, progname);

	if (verbose) {
		int family;
		fprintf(stderr, "List address family names and numbers:\n");
		for (family = 1; family < PF_NAMES_SIZE; family++)
			if (pf_names[family] != NULL)
				fprintf(stderr, "%5d: %s\n", family, pf_names[family]);
		fprintf(stderr, "\nMax family number %d\n", PF_EXTRA_SIZE - 1);
		fprintf(stderr, "\nAliases:\n"
				"  ip: inet,inet6,netlink,packet\n"
				"  ipv4: inet, ip4: inet, ipv6: inet6, ip6: inet6, bt: bluetooth, ir: irda\n\n");
	}
	exit(1);
}

int main(int argc, char *argv[])
{
	int c;
	int verbose = 0;
	int supported = 0;
	progname = basename(argv[0]);
	
	if (vu_getinfo(NULL) < 0) {
		fprintf(stderr, "%s is a vuos command\n", progname);
		return 1;
	}
	
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'f':
				process_families(optarg);
				break;
			case 'v':
				verbose = 1;
				break;
			case 's':
				supported = 1;
				break;
			case 'h':
			default:
				usage(argv[0], verbose);
				break;
		}
	}

	if (argc > optind + 1) {
		char *stack = argv[optind];
		char *cmd = argv[optind + 1];
		char **newargv = argv + (optind + 1);
		
		if (is_a_stack(stack) < 0) {
			perror(stack);
			exit(1);
		}

		if (supported)
			add_supported_families(stack);

		if (vustack_proto[PF_UNSPEC] == 1) {
			if (verbose)
				fprintf(stderr, "Using %s for ALL address families\n", stack);
			if (msocket(stack, 0, SOCK_DEFAULT, 0) < 0) {
				perror("vustack: msocket");
				exit(1);
			}
		} else {
			int family;
			if (verbose) {
				fprintf(stderr, "Using %s for the following address families:\n   ", stack);
				for(family = 1; family < PF_EXTRA_SIZE; family++) {
					if (vustack_proto[family] == 1) {
						fprintf(stderr," %s(%d)", pf_num2nname(family), family);
					}
				}
				fprintf(stderr,"\n");
			}
			for(family = 1; family < PF_EXTRA_SIZE; family++) {
				if (vustack_proto[family] == 1) {
					if (msocket(stack, family, SOCK_DEFAULT, 0) < 0) {
						perror("vustack: msocket");
						exit(1);
					}
				}
			}
		}

		execvp(cmd, newargv);
	} else
		usage(progname, verbose);
	return 1;
}
