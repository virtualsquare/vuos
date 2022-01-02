#ifndef _EVENT_SEM_H
#define _EVENT_SEM_H
#include <unistd.h>
#include <sys/eventfd.h>

static inline int sem_open(int init) {
	  return eventfd(init, EFD_SEMAPHORE | EFD_CLOEXEC);
}

static inline size_t sem_P(int fd) {
	uint64_t dummy;
	return read(fd, &dummy, sizeof(dummy));
}

static inline size_t sem_V(int fd) {
	static const uint64_t one = 1LL;
	return write(fd, &one, sizeof(one));
}

static inline int sem_close(int fd) {
	return close(fd);
}

#endif
