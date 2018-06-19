#ifndef VUFUSE_STARTMAIN_H
#define VUFUSE_STARTMAIN_H

struct main_params {
  int (*pmain)(int argc, char **argv);
  const char *filesystemtype;
  const char *source;
  const char *target;
  unsigned long *pmountflags;
  unsigned long *pfuseflags;
  char *opts;
};

int fusestartmain(struct main_params *mntp);

#endif
