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
			"  %s OPTIONS\n"
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
	size_t bufsize;
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
  if (argc - optind > 0)
    usage();
	if ((bufsize = vu_lsmod(NULL, 0)) > 0) {
		char buf[bufsize];
		if (vu_lsmod(buf, bufsize) < 0) 
			perror(progname);
		else
			printf("%s", buf);
	}
  return 0;
}
