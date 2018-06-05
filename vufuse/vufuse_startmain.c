#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <strcase.h>
#include <stropt.h>
#include <execs.h>
#include <vufuse.h>
#include <vufuse_startmain.h>

static struct {
	unsigned long flag;
	char *opt;
} optable[] = {
	{MS_RDONLY, "ro"},
	{MS_NOSUID, "nosuid"},
	{MS_NODEV, "nodev"},
	{MS_NOEXEC, "noexec"},
	{MS_SYNCHRONOUS, "sync"},
	{MS_REMOUNT, "remount"},
	/* XXX to be completed */
};
#define OPTABLE_LEN (sizeof(optable)/sizeof(optable[0]))

static int countflagoptions(unsigned long mountflags) {
	unsigned int i;
	int flagoptc;
  for (i = 0, flagoptc = 0; i < OPTABLE_LEN; i++) {
		if (mountflags & optable[i].flag)
			flagoptc++;
	}
	return flagoptc;
}

static void addflagoptions(char **tags, char **args, unsigned long mountflags) {
	unsigned int i;
	int flagoptc;
  for (i = 0, flagoptc = 0; i < OPTABLE_LEN; i++) {
		if (mountflags & optable[i].flag) {
			tags[flagoptc] = optable[i].opt;
			args[flagoptc] = NULL;
			flagoptc++;
		}
	}
	tags[flagoptc] = NULL;
	args[flagoptc] = NULL;
}

int fusestartmain(struct main_params *mntp) {
	int tagc = stropt(mntp->opts, NULL, NULL, 0) - 1;
	int flagtagc =  countflagoptions(*mntp->pflags);
	//printf("%d %d\n", tagc, flagtagc);
	char buf[strlen(mntp->opts)+1];
	char *newopts = NULL;
	char *format = "%T -o %O %S %M";
	int i;
	int retval;
	if(tagc + flagtagc == 0)
		newopts = strdup("rw");
	else {
		int tags_args_len = tagc + flagtagc + 1;
		char *tags[tags_args_len];
		char *args[tags_args_len];
		stropt(mntp->opts, tags, args, buf);
		for (i = 0; i < tagc; i++) {
			printf("%s =%s\n",tags[i],args[i]);
			switch(strcase(tags[i])) {
				case STRCASE(f,m,t): format = args[i]; tags[i] = STROPTX_DELETED_TAG; break;
														 /* here some opt could change bits in mntp->pflags */
			}
		}
		addflagoptions(tags+tagc, args+tagc, *mntp->pflags);
		newopts = stropt2str(tags, args, ',', '=');
	}
	printf("NEWOPTS = %s\n", newopts);
	printf("FORMAT = %s\n", format);
	char **xargv = s2argv(format);
	int xargc = s2argc(xargv);
	const char *argv[xargc + 2];
	int argc = 0;
	for (i = 0; i < xargc; i++) {
		switch(strcase(xargv[i])) {
			case STRCASE(perc,T):
				argv[argc++] = mntp->filesystemtype; break;
			case STRCASE(perc,O):
				argv[argc++] = newopts; break;
			case STRCASE(perc,S):
				if (mntp->source != NULL)
					argv[argc++] = mntp->source;
				break;
			case STRCASE(perc,M):
				if (mntp->target != NULL)
					argv[argc++] = mntp->target;
				break;
			default: argv[argc++] = xargv[i];
		}
	}
	argv[argc] = NULL;
	for (i = 0; i < argc; i++) {
		printf("%i %s\n",i,argv[i]);
	}
	retval = mntp->pmain(argc, argv, environ);
	s2argv_free(xargv);
	free(newopts);
	return retval;
}
