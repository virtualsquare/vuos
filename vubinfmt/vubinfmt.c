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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <strcase.h>
#include <stropt.h>
#include <vumodule.h>
#include <libvumod.h>

VU_PROTOTYPES(vubinfmt)

	struct vu_module_t vu_module = {
		.name = "vubinfmt",
		.description = "vu binfmt_misc support"
	};

struct vubinfmt_entry_t {
	struct vubinfmt_entry_t *next;
	ino_t ino;
	uint8_t enabled;
	char type;
	uint8_t offset;
	uint8_t len;
	uint8_t flags;
	uint8_t *magic;
	uint8_t *mask;
	char *interpreter;
	char name[];
};

struct vubinfmt_t {
	pthread_mutex_t mutex;
	uint8_t enabled;
	ino_t next_ino;
	struct vubinfmt_entry_t *head;
	struct vuht_entry_t *path_ht;
	struct vuht_entry_t *binfmt_ht;
};

static inline uint8_t encode_binfmt_flag(char c) {
	switch (c) {
		case 'P': return BINFMT_PRESERVE_ARGV0;
		case 'O': return BINFMT_OPEN_BINARY;
		case 'C': return BINFMT_CREDENTIALS;
		default: return 0;
	}
}

void dump_binfmt_flags(FILE *f, uint8_t flags) {
	if (flags & BINFMT_PRESERVE_ARGV0) fprintf(f,"P");
	if (flags & BINFMT_OPEN_BINARY) fprintf(f,"0");
	if (flags & BINFMT_CREDENTIALS) fprintf(f,"C");
}

void hexdump(FILE *f, uint8_t *data, int len) {
	int i;
	for (i = 0; i < len; i++)
		fprintf(f, "%02x", data[i]);
}

int hexescinput(char *src, uint8_t *data, int len) {
	int i;
	if (data) {
		memset(data, 0xff, len);
		for (i = 0; *src != 0 && i < len; src++, i++) {
			if (src[0] == '\\' && src[1] == 'x' && src[2] != 0 && src[3] != 0) {
				src += 2;
				sscanf(src, "%2hhx", &data[i]);
				src ++;
			} else {
				data[i] = *src;
			}
		}
	} else {
		for (i = 0; *src != 0 && i < len; src++, i++) {
			if (src[0] == '\\' && src[1] == 'x' && src[2] != 0 && src[3] != 0)
				src += 3;
		}
	}
	return i;
}

#define F_NULL        0
#define F_NAME        1
#define F_TYPE        2
#define F_OFFSET      3
#define F_MAGIC       4
#define F_MASK        5
#define F_INTERPRETER 6
#define F_FLAGS       7

int check_register_consistency(char **tags) {
	char *flag;
	// binfmt line begin by :
	if (tags[F_NULL][0] != 0) return 0;
	// NAME, not empty, can't be "status" or "register
	if (tags[F_NAME][0] == 0) return 0;
	if (strcmp(tags[F_NAME], "status") == 0) return 0;
	if (strcmp(tags[F_NAME], "register") == 0) return 0;
	// '/' is not permitted in name
	if (strchr(tags[F_NAME], '/') != NULL) return 0;
	// TYPE, must be either "M" or "E"
	if ((tags[F_TYPE][0] != 'M' && tags[F_TYPE][0] != 'E') ||
			tags[F_TYPE][1] != 0)
		return 0;
	// magic, not empty
	if (tags[F_MAGIC][0] == 0) return 0;
	// interpreter, not empty
	if (tags[F_INTERPRETER][0] == 0) return 0;
	// flags, check consistency
	//for (flag = tags[F_FLAGS]; flag && *flag; flag++)
	//printf("%c %d\n", *flag, encode_binfmt_flag(*flag));
	for (flag = tags[F_FLAGS]; flag && *flag; flag++)
		if (encode_binfmt_flag(*flag) == 0) return 0;
	return 1;
}

struct vubinfmt_entry_t *vubinfmt_newentry(char *input) {
	int tagc = stroptx(input, "", ":", STROPTX_ALLOW_MULTIPLE_SEP, NULL, NULL, 0);
	if (tagc == 9) {
		char *tags[tagc];
		char *args[tagc];
		stroptx(input, "", ":", STROPTX_ALLOW_MULTIPLE_SEP, tags, args, input);
		if (check_register_consistency(tags)) {
			int namelen = strlen(tags[F_NAME]) + 1;
			int interplen = strlen(tags[F_INTERPRETER]) + 1;
			int magiclen = hexescinput(tags[F_MAGIC], NULL, BINFMTBUFLEN);
			long offset = strtol(tags[F_OFFSET], NULL, 0);
			if (magiclen + offset <=  BINFMTBUFLEN) {
				char *flag;
				struct vubinfmt_entry_t *entry =
					malloc(sizeof(struct vubinfmt_entry_t) +
							namelen + interplen + 2 * magiclen);
				entry->enabled = 1;
				entry->type = tags[F_TYPE][0];
				entry->interpreter = entry->name + namelen;
				entry->magic = (uint8_t *) (entry->interpreter + interplen);
				entry->mask = entry->magic + magiclen;
				snprintf(entry->name, namelen, "%s", tags[F_NAME]);
				snprintf(entry->interpreter, interplen, "%s", tags[F_INTERPRETER]);
				entry->offset = offset;
				entry->len = magiclen;
				hexescinput(tags[F_MAGIC], entry->magic, magiclen);
				hexescinput(tags[F_MASK], entry->mask, magiclen);
				for (flag = tags[F_FLAGS], entry->flags = 0; flag && *flag; flag++)
					entry->flags |= encode_binfmt_flag(*flag);
				//for (int i=0; i<tagc; i++)
				//printf("%s = %s\n",tags[i], args[i]);
				return entry;
			}
		}
	}
	return NULL;
}

void vubinfmt_show(FILE *f, struct vubinfmt_entry_t *entry) {
	fprintf(f,"%sabled\n", (entry->enabled)?"en":"dis");
	fprintf(f,"interpreter %s\n", entry->interpreter);
	fprintf(f,"flags: ");
	dump_binfmt_flags(f, entry->flags);
	fprintf(f,"\n");
	fprintf(f,"offset %u\n", entry->offset);
	fprintf(f,"magic ");
	hexdump(f, entry->magic, entry->len);
	fprintf(f,"\n");
	if (entry->type == 'M') {
		fprintf(f,"mask ");
		hexdump(f, entry->mask, entry->len);
		fprintf(f,"\n");
	}
}

static struct vubinfmt_entry_t *vubinfmt_search(const char *name, struct vubinfmt_entry_t *head) {
	struct vubinfmt_entry_t *scan;
	for (scan = head; scan != NULL; scan = scan->next) {
		if (strcmp(scan->name, name) == 0)
			break;
	}
	return scan;
}

static struct vubinfmt_entry_t *vubinfmt_del(const char *name, struct vubinfmt_entry_t *head) {
	struct vubinfmt_entry_t **pscan;
	struct vubinfmt_entry_t *scan;
	for (pscan = &head, scan = *pscan; scan != NULL; pscan = &scan->next, scan = *pscan) {
		if (strcmp(scan->name, name) == 0) {
			*pscan = scan->next;
			free(scan);
		}
	}
	return head;
}

static int vubinfmt_match(struct binfmt_req_t *req, struct vubinfmt_entry_t *head) {
	struct vubinfmt_entry_t *scan;
	for (scan = head; scan != NULL; scan = scan->next) {
		if (scan->enabled) {
			if (scan->type == 'M') {
				int i,j,diff;
				for (i = scan->offset, j = 0, diff = 0;
						i < BINFMTBUFLEN && j < scan->len && diff == 0;
						i++, j++)
					diff = (req->filehead[i] ^ scan->magic[j]) & scan->mask[j];
				if (diff == 0)
					break;
			} else if (scan->type == 'E') {
				int suffixpos = strlen(req->path) - scan->len;
				if (suffixpos > 0 &&
						req->path[suffixpos - 1] == '.' &&
						strncmp(req->path + suffixpos, (const char *) scan->magic, scan->len)==0)
					break;
			}
		}
	}
	if (scan != NULL) {
		snprintf(req->filehead, BINFMTBUFLEN + 2, "#!%s", scan->interpreter);
		req->flags |= scan->flags;
		return 1;
	} else
		return 0;
}

static int vubinfmt_confirm(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vubinfmt_t *vubinfmt = vuht_get_private_data(ht);
	struct binfmt_req_t *req = arg;
	int retval;
	pthread_mutex_lock(&(vubinfmt->mutex));
	if (vubinfmt->enabled)
		retval = vubinfmt_match(req, vubinfmt->head);
	else
		retval = 0;
	pthread_mutex_unlock(&(vubinfmt->mutex));
	return retval;
}

int vu_vubinfmt_root_upcall(int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vubinfmt_t *vubinfmt = pseudoprivate;
	if (tag == PSEUDOFILE_LOAD_DIRENTS) {
		struct vubinfmt_entry_t *scan;
		pseudofile_filldir(f, ".", 2, DT_DIR);
		pseudofile_filldir(f, "..", 2, DT_DIR);
		pseudofile_filldir(f, "status", 3, DT_REG);
		pseudofile_filldir(f, "register", 4, DT_REG);
		for (scan = vubinfmt->head; scan != NULL; scan = scan->next)
			pseudofile_filldir(f, scan->name, scan->ino, DT_REG);
	}
	return 0;
}

int vu_vubinfmt_status_upcall(int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vubinfmt_t *vubinfmt = pseudoprivate;
	if (tag == PSEUDOFILE_LOAD_CONTENTS) {
		fprintf(f, "%sbled\n", vubinfmt->enabled == 0 ? "disa" : "ena");
	}
	if (tag == PSEUDOFILE_STORE_CLOSE) {
		int value;
		int valid = fscanf(f, "%d", &value);
		if (valid) {
			switch (value) {
				case 0:
				case 1:
					vubinfmt->enabled = value;
					break;
				case -1:
					while (vubinfmt->head != NULL)
						vubinfmt->head = vubinfmt_del(vubinfmt->head->name, vubinfmt->head);
					break;
			}
		}
	}
	return 0;
}

int vu_vubinfmt_register_upcall(int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vubinfmt_t *vubinfmt = pseudoprivate;
	if (tag == PSEUDOFILE_STORE_CLOSE) {
		char inbuf[BINFMTLINELEN + 1];
		size_t inbuflen = fread(inbuf, 1, BINFMTLINELEN, f);
		struct vubinfmt_entry_t *new;
		if (inbuf[inbuflen - 1] == '\n') inbuflen--;
		inbuf[inbuflen] = 0;
		new = vubinfmt_newentry(inbuf);
		if (new) {
			new->ino = vubinfmt->next_ino++;
			vubinfmt->head = vubinfmt_del(new->name, vubinfmt->head);
			new->next = vubinfmt->head;
			vubinfmt->head = new;
		}
	}
	return 0;
}

int vu_binfmt_entry_upcall (int tag, FILE *f, int openflags, void *pseudoprivate) {
	struct vubinfmt_entry_t *this = pseudoprivate;
	if (tag == PSEUDOFILE_LOAD_CONTENTS) {
		vubinfmt_show(f, this);
	}
	if (tag == PSEUDOFILE_STORE_CLOSE && (openflags & O_ACCMODE) != O_RDONLY) {
		int value;
		int valid = fscanf(f, "%d", &value);
		if (valid) {
			switch (value) {
				case 0:
				case 1:
					this->enabled = value;
					break;
				case -1:
					{
						struct vuht_entry_t *ht = vu_mod_getht();
						struct vubinfmt_t *vubinfmt = vuht_get_private_data(ht);
						vubinfmt->head = vubinfmt_del(this->name, vubinfmt->head);
					}
					break;
			}
		}
	}
	return 0;
}

int vu_vubinfmt_lstat(char *pathname, struct vu_stat *buf, int flags, int sfd, void *private) {
	struct vuht_entry_t *ht = vu_mod_getht();
	struct vubinfmt_t *vubinfmt = vuht_get_private_data(ht);
	int retval = 0;
	memset(buf, 0, sizeof(struct vu_stat));
	pthread_mutex_lock(&(vubinfmt->mutex));
	pathname++;
	switch(strcase(pathname)) {
		case 0:
			buf->st_mode = S_IFDIR | 0755;
			buf->st_ino = 2;
			break;
		case (STRCASE(s,t,a,t,u,s)):
			buf->st_mode = S_IFREG | 0644;
			buf->st_ino = 3;
			break;
		case (STRCASE(r,e,g,i,s,t,e,r)):
			buf->st_mode = S_IFREG | 0200;
			buf->st_ino = 4;
			break;
		default:
			{
				struct vubinfmt_entry_t *this;
				this = vubinfmt_search(pathname, vubinfmt->head);
				if (this) {
					buf->st_mode = S_IFREG | 0644;
					buf->st_ino = this->ino;
				} else {
					errno = ENOENT;
					retval = -1;
				}
			}
			break;
	}
	pthread_mutex_unlock(&(vubinfmt->mutex));
	return retval;
}

int vu_vubinfmt_open(const char *pathname, int flags, mode_t mode, void **fdprivate) {
	struct vuht_entry_t *ht = vu_mod_getht();
	struct vubinfmt_t *vubinfmt = vuht_get_private_data(ht);
	int retval = 0;
	pthread_mutex_lock(&(vubinfmt->mutex));
	pathname++;
	switch(strcase(pathname)) {
		case 0:
			if ((flags & O_ACCMODE) != O_RDONLY) {
				errno = EPERM;
				retval = -1;
			} else
				pseudofile_open(vu_vubinfmt_root_upcall, vubinfmt, flags, fdprivate);
			break;
		case (STRCASE(s,t,a,t,u,s)):
			pseudofile_open(vu_vubinfmt_status_upcall, vubinfmt, flags, fdprivate);
			break;
		case (STRCASE(r,e,g,i,s,t,e,r)):
			if ((flags & O_ACCMODE) != O_WRONLY) {
				errno = EPERM;
				retval = -1;
			} else
				pseudofile_open(vu_vubinfmt_register_upcall, vubinfmt, flags, fdprivate);
			break;
		default:
			{
				struct vubinfmt_entry_t *this;
				this = vubinfmt_search(pathname, vubinfmt->head);
				if (this) {
					pseudofile_open(vu_binfmt_entry_upcall, this, flags, fdprivate);
				} else {
					errno = ENOENT;
					retval = -1;
				}
			}
			break;
	}
	pthread_mutex_unlock(&(vubinfmt->mutex));
	return retval;
}

int vu_vubinfmt_mount(const char *source, const char *target,
		const char *filesystemtype, unsigned long mountflags,
		const void *data) {
	struct vu_service_t *s = vu_mod_getservice();
	struct vubinfmt_t *new = malloc(sizeof(struct vubinfmt_t));
	if (new == NULL)
		goto err_nomem_binfmt;
	pthread_mutex_init(&(new->mutex), NULL);
	pthread_mutex_lock(&(new->mutex));
	switch(strcase(source)) {
		case STRCASE(n,o,n,e):
		case STRCASE(slash):
			new->binfmt_ht = vuht_add(CHECKBINFMT, NULL, 0, s, vubinfmt_confirm, new, 0);
			break;
		default:
			new->binfmt_ht = vuht_add(CHECKBINFMT, source, strlen(source), s, vubinfmt_confirm, new, 0);
			break;
	}
	new->path_ht = vuht_pathadd(CHECKPATH, source, target, filesystemtype, mountflags, data, s, 0, NULL, new);
	new->enabled = 1;
	new->next_ino = 5;
	new->head = NULL;
	errno = 0;
	pthread_mutex_unlock(&(new->mutex));
	return 0;
err_nomem_binfmt:
	errno = ENOMEM;
	return -1;
}

int vu_vubinfmt_umount2(const char *target, int flags) {
	struct vuht_entry_t *ht = vu_mod_getht();
	int ret_value;
	if ((ret_value = vuht_del(ht, flags)) < 0) {
		errno = -ret_value;
		return -1;
	}
	return 0;
}

void vu_vubinfmt_cleanup(uint8_t type, void *arg, int arglen, struct vuht_entry_t *ht) {
	struct vubinfmt_t *vubinfmt = vuht_get_private_data(ht);
	switch (type) {
		case CHECKPATH:
			vubinfmt->path_ht = NULL;
			break;
		case CHECKBINFMT:
			vubinfmt->binfmt_ht = NULL;
			break;
	}
	if (vubinfmt->path_ht == NULL &&
			vubinfmt->binfmt_ht == NULL) {
		pthread_mutex_destroy(&(vubinfmt->mutex));
		free(vubinfmt);
	}
}

void *vu_vubinfmt_init(void) {
	struct vu_service_t *s = vu_mod_getservice();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	vu_syscall_handler(s, close) = pseudofile_close;
	vu_syscall_handler(s, read) = pseudofile_read;
	vu_syscall_handler(s, write) = pseudofile_write;
	vu_syscall_handler(s, lseek) = pseudofile_lseek;
	vu_syscall_handler(s, getdents64) = pseudofile_getdents64;
#pragma GCC diagnostic pop
	return NULL;
}

int vu_vubinfmt_fini(void *private) {
	return 0;
}

__attribute__((constructor))
	static void init(void) {
		debug_set_name(B, "VUBINFMT");
	}

__attribute__((destructor))
	static void fini(void) {
		debug_set_name(B, "");
	}

