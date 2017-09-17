#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <vu_name.h>

static pthread_mutex_t vu_name_mutex = PTHREAD_MUTEX_INITIALIZER;
static char vu_name[_UTSNAME_LENGTH];

void set_vu_name(char *name) {
	pthread_mutex_lock(&vu_name_mutex);
	memset(vu_name, 0, _UTSNAME_LENGTH);
	strncpy(vu_name, name, _UTSNAME_LENGTH);
	pthread_mutex_unlock(&vu_name_mutex);
}

void get_vu_name(char *name, size_t len) {
	if (len > _UTSNAME_LENGTH)
		len = _UTSNAME_LENGTH;
	pthread_mutex_lock(&vu_name_mutex);
	memcpy(name, vu_name, len);
	pthread_mutex_unlock(&vu_name_mutex);
}
