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

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <libgen.h>
#include <vulib.h>

static char *short_options = "c:ls:mph";
static struct option long_options[] = {
	{"command", 1, 0, 'c'},
	{"login", 0, 0, 'l'},
	{"shell", 1, 0, 's'},
	{"preserve-environment", 0, 0, 'p'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

char *command;
int login;
char *shell;
int change_environment = 1;
char *user;
int uid;
int gid;
char *arg0;
int ngroups;
gid_t *groups;

struct inheritenv {
	const char *tag;
	char *value;
} inheritenv[] = {
	{.tag = "TERM"},
	{.tag = "COLORTERM"},
	{.tag = "DISPLAY"},
	{.tag = "XAUTHORITY"},
	{NULL, NULL}
};

void usage(char *argv0)
{
	char *name=basename(argv0);
	fprintf(stderr,
			"Usage: %s [options] [LOGIN]\n"
			"\n"
			"Options:\n"
			"  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
			"  -h, --help                    display this help message and exit\n"
			"  -, -l, --login                make the shell a login shell\n"
			"  -m, -p,\n"
			"  --preserve-environment        do not reset environment variables, and\n"
			"                                keep the same shell\n"
			"  -s, --shell SHELL             use SHELL instead of the default in passwd\n"
			"\n",
			name
			);
	exit(2);
}

char *getlogindefs(char *tag) {
  char *line = NULL;
  size_t linelen = 0;
  FILE *f=fopen("/etc/login.defs","r");
  char *retvalue = NULL;
  if (f) {
    while (retvalue == NULL && getline(&line, &linelen, f) > 0) {
      char *s = line;
      while (*s==' ' || *s=='\t') s++;
      if (*s=='#') continue;
      if (strncmp(tag,s,strlen(tag))!=0) continue;
      s+=strlen(tag);
      if (*s != ' ' && *s != '\t') continue;
      while (*s==' ' || *s=='\t') s++;
      s[strlen(s)-1]=0;
      retvalue = strdup(s);
    }
    fclose(f);
    if (line) free(line);
  }
  return retvalue;
}

void setpath(void)
{
	char *tag = (uid==0)?"ENV_SUPATH":"ENV_PATH";
	char *path = getlogindefs(tag);
	if (path) {
		char *cleanpath = path;
		if (strncmp("PATH=",cleanpath,5) == 0)
			cleanpath += 5;
		setenv("PATH",cleanpath,1);
		free(path);
	} else {
		if (uid)
			path="/bin:/usr/bin";
		else
			path="/sbin:/bin:/usr/sbin:/usr/bin";
		setenv("PATH",path,1);
	}
}

void loginenv(void) {
	int i;
	for (i = 0; inheritenv[i].tag != NULL; i++) {
		char *value = getenv(inheritenv[i].tag);
		if (value)
			inheritenv[i].value = strdup(value);
	}
	clearenv();
	for (i = 0; inheritenv[i].tag != NULL; i++) {
		if (inheritenv[i].value) {
			setenv(inheritenv[i].tag, inheritenv[i].value, 1);
			free(inheritenv[i].value);
		}
	}
}
	
int main(int argc, char *argv[])
{
	int c;
	struct passwd *pwd;
	
	if (vu_getinfo(NULL) < 0)
		execvp("su",argv);
	
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_options,
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 'c': command=optarg;
								break;
			case 'l': login=1;
								break;
			case 's': shell=optarg;
								break;
			case 'm':
			case 'p': change_environment = 0;
								break;
			case 'h': usage(argv[0]);
								break;
			default:
								usage(argv[0]);
                break;
		}
	}

	if (argc > optind && strcmp(argv[optind],"-")==0) {
		login = 1;
		optind++;
	}

	if (argc > optind)
		user=argv[optind];

	if (argc > optind+1)
		usage(argv[0]);

	if (user == NULL)
		user = "root";

	pwd=getpwnam(user);
	if (pwd == NULL) {
		fprintf(stderr,"Unknown id: %s\n",user);
		exit(1);
	}
	uid=pwd->pw_uid;
	gid=pwd->pw_gid;
	if (login && change_environment)
		loginenv();

	if (shell == NULL) {
		if (change_environment)
			shell = pwd->pw_shell;
		else
			shell = getenv("SHELL");
	}
	if (shell == NULL)
		shell="/bin/sh";
	unsetenv("IFS");
	if (change_environment) {
		setenv("USER",user,1);
		setenv("LOGNAME",user,1);
		setenv("HOME",pwd->pw_dir,1);
		setenv("SHELL",shell,1);
	}
	if (login)
		asprintf(&arg0,"-%s",shell);
	else
		arg0=shell;
	getgrouplist(user,gid,NULL,&ngroups);
	groups=malloc(ngroups * sizeof (gid_t));
	if (groups == NULL)
		ngroups=0;
	else
		getgrouplist(user,gid,groups,&ngroups);

	if (setresuid(uid,uid,uid) < 0)
		perror(argv[0]);
	else {
		setresgid(gid,gid,gid);
		setgroups(ngroups,groups);
		setpath();
		if (login) {
			int defhome = 0;
			char *defhomeopt = getlogindefs("DEFAULT_HOME");
			if (defhomeopt) {
				if (strcmp(defhomeopt, "yes") == 0)
					defhome = 1;
				free(defhomeopt);
			}
			if (chdir(pwd->pw_dir) < 0) {
				if (defhome)
					chdir("/");
				else {
					perror(argv[0]);
					exit(1);
				}
			}
		}
		if (command)
			execl(shell,arg0,"-c",command,(char *)0);
		else
			execl(shell,arg0,(char *)0);
		perror(arg0);
	}
	exit(1);
	return 0;
}
