/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
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
 *   UMDEV: Virtual Device in Userspace
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <vu_file_table.h>
#include <hashtable.h>
#include <syscall_defs.h>
#include <service.h>
#include <r_table.h>

static int copyfile_in(struct vuht_entry_t *ht, char *path, char *tmp_path) {
  int fdin, fdout, n;
  char *buf[BUFSIZ];
  void *private;
  fdout = r_open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (fdout < 0)
    return -1;
  fdin = service_syscall(ht, __VU_open)(path, O_RDONLY, 0, &private);
  if (fdin < 0) {
		close(fdout);
		return -1;
	}
  while ((n = service_syscall(ht, __VU_read)(fdin, buf, BUFSIZ, private)) > 0)
    r_write(fdout, buf, n);
  service_syscall(ht, __VU_close)(fdin, private);
  r_close(fdout);
	return 0;
}

static int copyfile_out(struct vuht_entry_t *ht, char *path, char *tmp_path) {
  int fdin, fdout, n;
  char *buf[BUFSIZ];
  void *private;
	fdin = r_open(path, O_RDONLY);
  if (fdin < 0)
    return -1;
  fdout = service_syscall(ht, __VU_open)(path, O_RDWR, 0, &private);
  if (fdout < 0) {
		close(fdin);
		return -1;
	}
  while ((n = r_read(fdin, buf, BUFSIZ)) > 0) 
		service_syscall(ht, __VU_write)(fdin, buf, n, private);
  service_syscall(ht, __VU_close)(fdin, private);
  r_close(fdout);
	return 0;
}

int vu_fnode_copyin(struct vu_fnode_t *fnode) {
	return vu_fnode_copyinout(fnode, copyfile_in);
}

int vu_fnode_copyout(struct vu_fnode_t *fnode) {
	return vu_fnode_copyinout(fnode, copyfile_out);
}
