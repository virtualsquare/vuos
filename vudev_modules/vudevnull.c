/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   with contributions by Alessio Volpe <alessio.volpe3@studio.unibo.it>
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vudev.h>
#include <vumodule.h>

static int null_open(const char *pathname, mode_t mode, struct vudevfd_t *vdefd) {
  printkdebug(D,"null_open [%s]", pathname);
  return 0;
}

static int null_close(struct vudevfd_t *vdefd) {
  printkdebug(D,"null_close", NULL);
  return 0;
}

static ssize_t null_read (struct vudevfd_t *vdefd, void *buf, size_t count) {
  printkdebug(D,"null_read: [%d]", count);
  return 0;
}

static ssize_t null_write(struct vudevfd_t *vdefd, const void *buf, size_t count) {
  printkdebug(D,"null_write: [%d]", count);
  return count;
}

struct vudev_operations_t vudev_ops = {
  .open = null_open,
  .close = null_close,
  .read = null_read,
  .write= null_write,
};

