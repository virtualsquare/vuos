#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <getopt.h>
#include <vulib.h>

#define ALLTAGS "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n"
static char *progname;
void usage()
{
  fprintf(stderr, 
			"Usage: %s [ARG] [ARG] ..."
			"  ARG = --help | DEBUGSPEC\n"
			"  DEBUGSPEC = [+|-]TAG[TAG]...[:COLORSPEC]\n"
			"  +: add, -: delete ?:ls\n"
			"  TAG one of: " ALLTAGS "\n"
			"  COLORSPEC: nwrgbcmyNWRGBCMY+-_*#\n"
			"  nwrgbcmy = black white red green blue cyan magenta yellow"
			"  smallcase: foreground, capital: background"
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
	int c;
	vu_get_debugtags(tags, DEBUG_NTAGS+1);
	for (c = ' '; c < 128; c++) {
		int tagselected = !!strchr(tags, c);
		char tagname[32];
		vu_get_debugtagname(c, tagname, 32);
		if (((lstags != NULL && strchr(lstags, c)) ||
				 (lstags == NULL && (tagselected || *tagname != '\0'))))	
			printf("%c %c %s\n", c, tagselected ? '+' : '-', tagname);
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
    vu_get_debugtags(tags, DEBUG_NTAGS+1);
    printf("%s\n",tags);
	}
	else if (argc == 2 && strcmp(argv[1], "--help") == 0)
		usage();
	else {
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
				case '+': vu_add_debugtags(*tags ? tags : ALLTAGS);
									break;
				case '-': vu_del_debugtags(*tags ? tags : ALLTAGS);
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
	}
	return 0;
}

