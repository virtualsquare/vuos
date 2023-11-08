/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it> VirtualSquare team.
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
#include<fcntl.h>
#include<stdlib.h>
#include<string.h>
#include<dirent.h>
#include<errno.h>
#include<stddef.h>
#include<sys/stat.h>
#include<vumodule.h>
#include<libvumod.h>
#include<volatilestream.h>

typedef int (* pseudo_upcall)(int tag, FILE *f, int openflags, void *pseudoprivate);

struct pseudofile {
	pseudo_upcall upcall;
	void *pseudoprivate;
	int flags;
	FILE *f;
	char *ptr;
	size_t len;
};

int pseudofile_mode2type(mode_t mode) {
	if (S_ISREG(mode))
		return DT_REG;
	else if (S_ISDIR(mode))
		return DT_DIR;
	else if (S_ISLNK(mode))
		return DT_LNK;
	else if (S_ISCHR(mode))
		return DT_CHR;
	else if (S_ISBLK(mode))
		return DT_BLK;
	else if (S_ISSOCK(mode))
		return DT_SOCK;
	else if (S_ISFIFO(mode))
		return DT_FIFO;
	else
		return DT_UNKNOWN;
}

ssize_t pseudofile_readlink_fill(char *path, char *buf, size_t bufsiz) {
	if (path == NULL) {
		errno = EINVAL;
		return -1;
	} else {
		size_t len = strlen(path);
		if (len > bufsiz) len = bufsiz;
		mempcpy(buf, path, len);
		if (len < bufsiz)
			buf[len] = 0;
		return len;
	}
}

int pseudofile_filldir(FILE *f, char *name, ino_t ino, char type) {
	struct dirent64 entry = {
		.d_ino = ino,
		.d_type = type
	};
	static char filler[7];
	unsigned short int namelen = strlen(name) + 1;
	unsigned short int reclen  = offsetof(struct dirent64, d_name) + namelen;
	int ret_value;
	snprintf(entry.d_name, 256, "%s", name);
	/* entries are always 8 bytes aligned */
	entry.d_reclen = (reclen + 7) & (~7);
	ret_value = fwrite(&entry, reclen, 1, f);
	/* add a filler to align the next entry */
	if (entry.d_reclen > reclen)
		ret_value += fwrite(filler, entry.d_reclen - reclen, 1, f);
	return ret_value;
}

int pseudofile_open(pseudo_upcall upcall, void *pseudoprivate, int flags, void **private) {
	struct pseudofile *pseudofile = malloc(sizeof(struct pseudofile));

	pseudofile->upcall = upcall;
	pseudofile->pseudoprivate = pseudoprivate;
	pseudofile->flags = flags;
	pseudofile->f = NULL;
	pseudofile->ptr = NULL;
	pseudofile->len = 0;

	*private = pseudofile;
	return 0;
}

static void pseudofile_load_contents(struct pseudofile *pseudofile) {
	pseudofile->f = open_memstream(&pseudofile->ptr, &pseudofile->len);
	if ((pseudofile->flags & O_ACCMODE) != O_WRONLY && !(pseudofile->flags & O_TRUNC)) {
		pseudofile->upcall(PSEUDOFILE_LOAD_CONTENTS, pseudofile->f, pseudofile->flags, pseudofile->pseudoprivate);
		fflush(pseudofile->f);
		fseeko(pseudofile->f, 0, SEEK_SET);
	}
}

int pseudofile_close(int fd, void *private) {
	struct pseudofile *pseudofile = private;

	if (pseudofile) {
		if (pseudofile->f)
			fseeko(pseudofile->f, 0, SEEK_SET);
		pseudofile->upcall(PSEUDOFILE_STORE_CLOSE, pseudofile->f, pseudofile->flags, pseudofile->pseudoprivate);
		if (pseudofile->f)
			fclose(pseudofile->f);
		if (pseudofile->ptr)
			free(pseudofile->ptr);
		free(pseudofile);
	}
	return 0;
}

int pseudofile_read(int fd, void *buf, size_t count, void *private) {
	struct pseudofile *pseudofile = private;
	if (pseudofile == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((pseudofile->flags & O_ACCMODE) == O_WRONLY) {
		errno = EBADF;
		return -1;
	}
	if (pseudofile->f == NULL)
		pseudofile_load_contents(pseudofile);
	return fread(buf, 1, count, pseudofile->f);
}

int pseudofile_write(int fd, const void *buf, size_t count, void *private) {
	struct pseudofile *pseudofile = private;
	if (pseudofile == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((pseudofile->flags & O_ACCMODE) == O_RDONLY) {
		errno = EBADF;
		return -1;
	}
	if (pseudofile->f == NULL)
		pseudofile_load_contents(pseudofile);
	return fwrite(buf, 1, count, pseudofile->f);
}

int pseudofile_lseek(int fd, off_t offset, int whence, void *private) {
	struct pseudofile *pseudofile = private;
	if (pseudofile == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (pseudofile->f == NULL)
		pseudofile_load_contents(pseudofile);
	return fseeko(pseudofile->f, offset, whence);
}

int pseudofile_getdents64(int fd,  struct dirent64 *dirp,
		unsigned int count, void *private) {
	struct pseudofile *pseudofile = private;
	size_t freadout;
	if (pseudofile == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (pseudofile->f == NULL) {
		pseudofile->f = volstream_open();
		pseudofile->upcall(PSEUDOFILE_LOAD_DIRENTS, pseudofile->f, pseudofile->flags, pseudofile->pseudoprivate);
		fflush(pseudofile->f);
		fseeko(pseudofile->f, 0, SEEK_SET);
	}
	freadout = fread(dirp, 1, count, pseudofile->f);
	/* if the buffer is full the last entry might be incomplete.
		 update freadout to drop the last incomplete entry,
		 and seek back the position in the file to reread it
		 from its beginning at the next getdents64 */
	if (freadout == count) {
		unsigned int bpos = 0;
		struct dirent64 *d;
		char *buf = (char *) dirp;
		while (1) {
			d = (struct dirent64 *) (buf + bpos);
			if (count - bpos < offsetof(struct dirent64, d_name))
				break;
			if (bpos + d->d_reclen > count)
				break;
			bpos += d->d_reclen;
		}
		if (bpos < count) {
			fseeko(pseudofile->f, - (int) (count - bpos), SEEK_CUR);
			freadout -= count - bpos;
		}
		/* the buffer is so short that it does not fit one
			 entry. Return EINVAL! */
		if (freadout == 0) {
			errno = EINVAL;
			return -1;
		}
	}
	return freadout;
}
