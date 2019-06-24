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
#include <string.h>
#include <libgen.h>
#include <getopt.h>
#include <vulib.h>

#define ALLTAGS "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
static char *progname;
void usage()
{
  fprintf(stderr,
			"Usage: %s [ARG] [ARG] ... [ -- cmd args ]\n"
			"  ARG = --help | DEBUGSPEC\n"
			"  DEBUGSPEC = [+|-]TAG[TAG]...[:COLORSPEC]\n"
			"  +: add, -: delete ?:ls\n"
			"  TAG one of: " ALLTAGS "\n"
			"  COLORSPEC: nwrgbcmyNWRGBCMY+-_*#\n"
			"  nwrgbcmy = black white red green blue cyan magenta yellow\n"
			"  smallcase: foreground, capital: background\n"
			"  +:,bright, -: dim, _: underlined, *: blinking,  #: reverse\n\n",
			progname);

  exit(2);
}

static inline void unique(int c) {
	if (c != 0)
		usage();
}



static void vu_ls_debugtags(char *lstags) {
	char tags[DEBUG_NTAGS+1];
	char ltags[DEBUG_NTAGS+1];
	int c;
	vu_get_debugtags(tags, DEBUG_NTAGS+1, 0);
	vu_get_debugtags(ltags, DEBUG_NTAGS+1, 1);
	for (c = ' '; c < 128; c++) {
		int tagselected = !!strchr(tags, c);
		int ltagselected = !!strchr(ltags, c);
		char tagname[32];
		vu_get_debugtagname(c, tagname, 32);
		if (((lstags != NULL && strchr(lstags, c)) ||
				 (lstags == NULL && (tagselected || *tagname != '\0'))))	
			printf("%c %c%s%s\n", c,
					tagselected ? '+' : '-',
					ltagselected ? "(+)" : "   ",
					tagname);
	}
}

static char functions[] = "+-?";
int main(int argc, char *argv[])
{
	progname = basename(argv[0]);
  if (vu_check() < 0) {
    fprintf(stderr,"This is a VUOS command."
				"It works only inside a vuos virtual namespace\n");
    usage();
  }
	if (argc == 1) {
		char tags[DEBUG_NTAGS+1];
		char ltags[DEBUG_NTAGS+1];
    vu_get_debugtags(tags, DEBUG_NTAGS+1, 0);
    vu_get_debugtags(ltags, DEBUG_NTAGS+1, 1);
		if (*tags)
			printf("%s\n",tags);
		if (*ltags)
			printf("(%s)\n",ltags);
	}
	else if (argc == 2 && strcmp(argv[1], "--help") == 0)
		usage();
	else {
		int i;
		char **cmdargv = NULL;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--") == 0) {
				argc = i;
				cmdargv = argv + i + 1;
				break;
			}
		}
		for (argc--, argv++; argc > 0; argc--, argv++) {
			char *arg = strdup(argv[0]);
			char *tags = arg;
			char function = 0;
			char *color;
			if (strchr(functions, *arg))
				function = *tags++;
			if ((color = strchr(tags, ':')) != NULL)
				*color++ = 0;
			switch (function) {
				case '+': vu_add_debugtags(*tags ? tags : ALLTAGS, cmdargv != NULL);
									break;
				case '-': vu_del_debugtags(*tags ? tags : ALLTAGS, cmdargv != NULL);
									break;
				case '?': vu_ls_debugtags(*tags ? tags : NULL);
									break;
				default:  if (color == NULL)
									 usage();
									break;
			}
			if (color) {
				char *colorstring;
				asprintf(&colorstring, "%s:%s", *tags ? tags : ALLTAGS, color);
				vu_set_debugcolor(colorstring);
				free(colorstring);
			}
			free(arg);
		}
		if (cmdargv != NULL)
			execvp(cmdargv[0], cmdargv);
	}
	return 0;
}

