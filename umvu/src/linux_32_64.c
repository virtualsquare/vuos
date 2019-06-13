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
 *
 */

#include <string.h>
#include <dirent.h>
#include <vu_log.h>
#include <linux_32_64.h>

/* convert dirent64 to dirent:
	 VUOS modules handle 64bit dirents, this conversion is needed to
	 support 32bit dirent (on 32bit architectures) */
void dirent64_to_dirent(void* buf, int count){
  struct linux_dirent *dirp=buf;
  struct dirent64 *dirp64=buf;
  int counter=0;
  unsigned short int buf_len;

	/* Actually the conversion is a bit tricky.
	 * dirent is always shorter then dirent64.
	 * copy the corresponding fields
	 * keep the record length (there will be some unused bytes) */
  for( counter=0; counter<count ; ){
    char tmptype;
    dirp->d_ino = (unsigned long) dirp64->d_ino;
    dirp->d_off = (unsigned long) dirp64->d_off;
    buf_len = dirp->d_reclen = dirp64->d_reclen;
    tmptype = dirp64->d_type;
    memmove(dirp->d_name,dirp64->d_name,strlen(dirp64->d_name)+1);
    *((char *) dirp + buf_len - 1)=tmptype;
    counter= counter + dirp->d_reclen; //bad...
    dirp = (struct linux_dirent *) ((char*)dirp + buf_len);
    dirp64 = (struct dirent64 *) ((char*)dirp64 + buf_len);
  }
}


