/*
 *   VUOS: view OS project
 *   Copyright (C) 2020  Renzo Davoli <renzo@cs.unibo.it>
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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <ctype.h>
#include <linux/elf.h>

#include <linux_32_64.h>
#include <r_table.h>
#include <hashtable.h>
#include <syscall_defs.h>
#include <service.h>
#include <vu_fs.h>

static char *elf_magic = "\177ELF";

void exec_chroot_rewrite_interpreter(struct vuht_entry_t *ht, struct binfmt_req_t *req) {
	char *e_ident = req->filehead;
	void *private = NULL;
	int fd;
	int i;
	char interpath[BINFMTBUFLEN - 1];
	if (memcmp(e_ident,  elf_magic, strlen(elf_magic)) != 0)
		return;
	if (e_ident[EI_DATA] != 0x01) // little endian
		return;
	if (e_ident[EI_VERSION] != 0x01) // version 1
		return;
	vu_fs_get_rootdir(interpath, sizeof(interpath));
	if (ht) {
		if ((fd = service_syscall(ht, __VU_open)
					(vuht_path2mpath(ht, req->path), O_RDONLY, 0, &private)) < 0)
			return;
		if (e_ident[EI_CLASS] == 01) {
			// virtual 32
			Elf32_Ehdr *hdr = (Elf32_Ehdr *) req->filehead;
			if (service_syscall(ht, __VU_lseek)(fd, hdr->e_phoff, SEEK_SET, private) < 0)
        goto close_return_ht;
      Elf32_Phdr phdr[hdr->e_phnum];
      if (service_syscall(ht, __VU_read)(fd, phdr, sizeof(phdr), private) != ((int) sizeof(phdr)))
        goto close_return_ht;
      for (i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP)
          break;
      }
      if (i >= hdr->e_phnum)
        goto close_return_ht;
      int interlen = strlen(interpath);
      if (interlen + phdr[i].p_filesz >= sizeof(interpath))
        goto close_return_ht;
      if (service_syscall(ht, __VU_lseek)(fd, phdr[i].p_offset, SEEK_SET, private) < 0)
        goto close_return_ht;
      if (service_syscall(ht, __VU_read)
					(fd, interpath + interlen, phdr[i].p_filesz, private) != ((int) phdr[i].p_filesz))
        goto close_return_ht;
		} else if (e_ident[EI_CLASS] == 02) {
			// virtual 64
			Elf64_Ehdr *hdr = (Elf64_Ehdr *) req->filehead;
			if (service_syscall(ht, __VU_lseek)(fd, hdr->e_phoff, SEEK_SET, private) < 0)
				goto close_return_ht;
			Elf64_Phdr phdr[hdr->e_phnum];
			if (service_syscall(ht, __VU_read)(fd, phdr, sizeof(phdr), private) != ((int) sizeof(phdr)))
				goto close_return_ht;
			for (i = 0; i < hdr->e_phnum; i++) {
				if (phdr[i].p_type == PT_INTERP)
					break;
			}
			if (i >= hdr->e_phnum)
				goto close_return_ht;
			int interlen = strlen(interpath);
			if (interlen + phdr[i].p_filesz >= sizeof(interpath))
				goto close_return_ht;
      if (service_syscall(ht, __VU_lseek)(fd, phdr[i].p_offset, SEEK_SET, private) < 0)
				goto close_return_ht;
      if (service_syscall(ht, __VU_read)
					(fd, interpath + interlen, phdr[i].p_filesz, private) != ((int) phdr[i].p_filesz))
				goto close_return_ht;
		} else
			goto close_return_ht;
		snprintf(req->filehead, BINFMTBUFLEN + 2, "#!%s\n", interpath);
close_return_ht:
		service_syscall(ht, __VU_close)(fd, private);
	} else {
		if ((fd = r_open(req->path, O_RDONLY)) < 0)
			return;
		if (e_ident[EI_CLASS] == 01) {
			// real 32
      Elf32_Ehdr *hdr = (Elf32_Ehdr *) req->filehead;
      if (r_lseek(fd, hdr->e_phoff, SEEK_SET) < 0)
        goto close_return;
      Elf32_Phdr phdr[hdr->e_phnum];
      if (r_read(fd, phdr, sizeof(phdr)) != ((int) sizeof(phdr)))
        goto close_return;
      for (i = 0; i < hdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_INTERP)
          break;
      }
      if (i >= hdr->e_phnum)
        goto close_return;
      int interlen = strlen(interpath);
      if (interlen + phdr[i].p_filesz >= sizeof(interpath))
        goto close_return;
      if (lseek(fd, phdr[i].p_offset, SEEK_SET) < 0)
        goto close_return;
      if (r_read(fd, interpath + interlen, phdr[i].p_filesz) != ((int) phdr[i].p_filesz))
        goto close_return;
		} else if (e_ident[EI_CLASS] == 02) {
			// real 64
			Elf64_Ehdr *hdr = (Elf64_Ehdr *) req->filehead;
			if (r_lseek(fd, hdr->e_phoff, SEEK_SET) < 0)
				goto close_return;
			Elf64_Phdr phdr[hdr->e_phnum];
			if (r_read(fd, phdr, sizeof(phdr)) != ((int) sizeof(phdr)))
				goto close_return;
			for (i = 0; i < hdr->e_phnum; i++) {
				if (phdr[i].p_type == PT_INTERP)
					break;
			}
			if (i >= hdr->e_phnum)
				goto close_return;
			int interlen = strlen(interpath);
			if (interlen + phdr[i].p_filesz >= sizeof(interpath))
				goto close_return;
			if (lseek(fd, phdr[i].p_offset, SEEK_SET) < 0)
				goto close_return;
			if (r_read(fd, interpath + interlen, phdr[i].p_filesz) != ((int) phdr[i].p_filesz))
				goto close_return;
		} else
			goto close_return_ht;
		snprintf(req->filehead, BINFMTBUFLEN + 2, "#!%s\n", interpath);
close_return:
		r_close(fd);
	}
}
