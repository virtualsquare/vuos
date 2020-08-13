#ifndef VUFSA_H
#define VUFSA_H

struct vufs_t;

typedef int8_t vufsa_status;

/* type of FSA next function */
typedef vufsa_status (*vufsa_next)(vufsa_status status, struct vufs_t *vufs, const char *path, int rv);

/* select the right FSA depending upon the mount mode and open flags */
vufsa_next vufsa_select(struct vufs_t *vufs, int open_flags);

#define VUFSA_ERR -1
#define VUFSA_EXIT 0
#define VUFSA_START 1
#define VUFSA_FINAL 2
#define VUFSA_DOREAL 3
#define VUFSA_DOVIRT 4
#define VUFSA_DOCOPY 5
#define VUFSA_VUNLINK 5

#if 0
/* usage: */
int rv;
vufsa_status status = VUFSA_START;
vufsa_next vufsa_next = vufsa_select(vufs, openflag);
while ((status = vufsa_next(status, vufs, path, openflag, 0, rv)) != VUFSA_EXIT) {
	switch (status) {
		case VUFSA_DOREAL:
			rv = /* implementation of do_real for this syscall */
				break;
		case VUFSA_DOVIRT:
			rv = /* implementation of do_virtual for this syscall */
				break;
		case VUFSA_DOCOPY:
			rv = /* implementation of do_copy for this syscall */
				break;
		case VUFSA_ERR:
			rv = -1;
			break;
	}
#endif

#endif
