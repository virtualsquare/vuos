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
			"    -p --permanent:  rmmod forbidden\n\n"
			"    -h --help:  print this help message\n\n", progname);

  exit(2);
}

static const char *short_options = "p";
static const struct option long_options[] = {
	{"permanent",0,0,'p'},
	{"help",0,0,'h'},
	{0,0,0,0}
};

int main(int argc, char *argv[])
{
  int c;
  int permanent=0;
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
      case 'p': permanent=1;
                break;
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
      if (vu_insmod(argv[i], permanent) < 0) {
        perror(argv[i]);
        rv=1;
      }
    }
    return rv;
  }
  return 0;
}

