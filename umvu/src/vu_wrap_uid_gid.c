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
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/syscall.h>
#include <syscall_defs.h>
#include <xcommon.h>
#include <hashtable.h>
#include <service.h>
#include <epoch.h>
#include <vu_log.h>
#include <umvu_peekpoke.h>
#include <vu_wrapper_utils.h>
#include <vu_execute.h>
#include <vu_uidgid.h>

void wi_getresfuid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int syscall_number = sd->syscall_number;
	uid_t current_ruid, current_euid, current_suid, current_fsuid;
	if (ht) {
		service_syscall(ht, __VU_getresfuid)(&current_ruid, &current_euid, &current_suid, &current_fsuid, vuht_get_private_data(ht));
	} else {
		vu_uidgid_getresfuid(&current_ruid, &current_euid, &current_suid, &current_fsuid);
	}
	switch (syscall_number) {
		case __NR_getuid:
			sd->ret_value = current_ruid;
			break;
		case __NR_geteuid:
			sd->ret_value = current_euid;
			break;
		case __NR_getresuid:
			{
				uintptr_t addr_ruid = sd->syscall_args[0];
				uintptr_t addr_euid = sd->syscall_args[1];
				uintptr_t addr_suid = sd->syscall_args[2];
				if (addr_ruid != 0) {
					uid_t *pruid;
					vu_alloc_local_arg(addr_ruid, pruid, sizeof(uid_t), nested);
					*pruid = current_ruid;
					vu_poke_arg(addr_ruid, pruid, sizeof(uid_t), nested);
				}
				if (addr_euid != 0) {
					uid_t *peuid;
					vu_alloc_local_arg(addr_euid, peuid, sizeof(uid_t), nested);
					*peuid = current_euid;
					vu_poke_arg(addr_euid, peuid, sizeof(uid_t), nested);
				}
				if (addr_suid != 0) {
					uid_t *psuid;
					vu_alloc_local_arg(addr_suid, psuid, sizeof(uid_t), nested);
					*psuid = current_suid;
					vu_poke_arg(addr_suid, psuid, sizeof(uid_t), nested);
				}
				sd->ret_value = 0;
			}
			break;
	}
	sd->action = SKIPIT;
}

void wi_getresfgid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	int syscall_number = sd->syscall_number;
	gid_t current_rgid, current_egid, current_sgid, current_fsgid;
	if (ht) {
		service_syscall(ht, __VU_getresfgid)(&current_rgid, &current_egid, &current_sgid, &current_fsgid, vuht_get_private_data(ht));
	} else {
		vu_uidgid_getresfgid(&current_rgid, &current_egid, &current_sgid, &current_fsgid);
	}
	switch (syscall_number) {
		case __NR_getgid:
			sd->ret_value = current_rgid;
			break;
		case __NR_getegid:
			sd->ret_value = current_egid;
			break;
		case __NR_getresgid:
			{
				uintptr_t addr_rgid = sd->syscall_args[0];
				uintptr_t addr_egid = sd->syscall_args[1];
				uintptr_t addr_sgid = sd->syscall_args[2];
				if (addr_rgid != 0) {
					gid_t *prgid;
					vu_alloc_local_arg(addr_rgid, prgid, sizeof(gid_t), nested);
					*prgid = current_rgid;
					vu_poke_arg(addr_rgid, prgid, sizeof(gid_t), nested);
				}
				if (addr_egid != 0) {
					gid_t *pegid;
					vu_alloc_local_arg(addr_egid, pegid, sizeof(gid_t), nested);
					*pegid = current_egid;
					vu_poke_arg(addr_egid, pegid, sizeof(gid_t), nested);
				}
				if (addr_sgid != 0) {
					gid_t *psgid;
					vu_alloc_local_arg(addr_sgid, psgid, sizeof(gid_t), nested);
					*psgid = current_sgid;
					vu_poke_arg(addr_sgid, psgid, sizeof(gid_t), nested);
				}
				sd->ret_value = 0;
			}
			break;
	}
	sd->action = SKIPIT;
}

void wi_getgroups(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int ret_value;
	int nested = sd->extra->nested;
	int size = sd->syscall_args[0];
	uintptr_t listaddr =  sd->syscall_args[1];
	gid_t *list;
	vu_alloc_arg(listaddr, list, size * sizeof(gid_t), nested);
	if (ht) {
		ret_value = service_syscall(ht, __VU_getgroups)(size, list, vuht_get_private_data(ht));
	} else {
		ret_value = vu_uidgid_getgroups(size, list);
		if (ret_value < 0)
			errno = EINVAL;
	}
	if (ret_value > 0)
		vu_poke_arg(listaddr, list, ret_value * sizeof(gid_t), nested);
	vu_free_arg(list, nested);
	sd->action = SKIPIT;
	if (ret_value < 0)
		sd->ret_value = -errno;
	else
		sd->ret_value = ret_value;
}

static void wi_setresuid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		int syscall_number = sd->syscall_number;
		uid_t ruid, euid, suid, fsuid;
		uid_t new_ruid, new_euid, new_suid;
		int ret_value = -1;
		service_syscall(ht, __VU_getresfuid) (&ruid, &euid, &suid, &fsuid, vuht_get_private_data(ht));
		switch (syscall_number) {
			case __NR_setuid:
				new_ruid = -1;
				new_euid = sd->syscall_args[0];
				new_suid = -1;
				if (new_euid != (uid_t) -1 && euid == 0)
					new_ruid = new_suid = new_euid;
				break;
			case __NR_setreuid:
				new_ruid = sd->syscall_args[0];
				new_euid = sd->syscall_args[1];
				new_suid = -1;
				/* If the real user ID is set (i.e., ruid is not -1) or the effective user ID is set to a value
					 not  equal to the previous real user ID, the saved set-user-ID will be set to the new effec-
					 tive user ID. */
				if (new_ruid != (uid_t) -1 || (new_euid != (uid_t) -1 && new_euid != ruid))
					new_suid = (new_euid == (uid_t) -1) ? euid : new_euid;
				break;
			case __NR_setresuid:
				new_ruid = sd->syscall_args[0];
				new_euid = sd->syscall_args[1];
				new_suid = sd->syscall_args[2];
				break;
		}
		if (new_ruid != (uid_t) -1)
			ruid = new_ruid;
		if (new_euid != (uid_t) -1 && euid != new_euid)
			euid = fsuid = new_euid;
		if (new_suid != (uid_t) -1)
			suid = new_suid;
		if (syscall_number == __NR_setresuid)
			fsuid = euid;
		ret_value = service_syscall(ht, __VU_setresfuid)(ruid, euid, suid, fsuid, vuht_get_private_data(ht));
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
		sd->action = SKIPIT;
	} else if (nested) {
		sd->ret_value = -ENOSYS;
		sd->action = SKIPIT;
	} else { // !ht && !nested
		sd->action = DOIT_CB_AFTER;
	}
}

static void wi_setresgid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		int syscall_number = sd->syscall_number;
		uid_t euid;
		gid_t rgid, egid, sgid, fsgid;
		gid_t new_rgid, new_egid, new_sgid;
		int ret_value = -1;
		service_syscall(ht, __VU_getresfuid) (NULL, &euid, NULL, NULL, vuht_get_private_data(ht));
		service_syscall(ht, __VU_getresfgid) (&rgid, &egid, &sgid, &fsgid, vuht_get_private_data(ht));
		switch (syscall_number) {
			case __NR_setgid:
				new_rgid = -1;
				new_egid = sd->syscall_args[0];
				new_sgid = -1;
				if (new_egid != (gid_t) -1 && euid == 0)
					new_rgid = new_sgid = new_egid;
				break;
			case __NR_setregid:
				new_rgid = sd->syscall_args[0];
				new_egid = sd->syscall_args[1];
				new_sgid = -1;
				/* If the real user ID is set (i.e., rgid is not -1) or the effective user ID is set to a value
					 not  equal to the previous real user ID, the saved set-user-ID will be set to the new effec-
					 tive user ID. */
				if (new_rgid != (gid_t) -1 || (new_egid != (gid_t) -1 && new_egid != rgid))
					new_sgid = (new_egid == (gid_t) -1) ? egid : new_egid;
				break;
			case __NR_setresgid:
				new_rgid = sd->syscall_args[0];
				new_egid = sd->syscall_args[1];
				new_sgid = sd->syscall_args[2];
				break;
		}
		if (new_rgid != (gid_t) -1)
			rgid = new_rgid;
		if (new_egid != (gid_t) -1 && egid != new_egid)
			egid = fsgid = new_egid;
		if (new_sgid != (gid_t) -1)
			sgid = new_sgid;
		if (syscall_number == __NR_setresgid)
			fsgid = egid;
		ret_value = service_syscall(ht, __VU_setresfgid)(rgid, egid, sgid, fsgid, vuht_get_private_data(ht));
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
		sd->action = SKIPIT;
	} else if (nested) {
		sd->ret_value = -ENOSYS;
		sd->action = SKIPIT;
	} else { // !ht && !nested
		sd->action = DOIT_CB_AFTER;
	}
}

static void wi_setfsuid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	uid_t new_fsuid = sd->syscall_args[0];
	if (ht) {
		uid_t ruid, euid, suid, fsuid;
		service_syscall(ht, __VU_getresfuid)(&ruid, &euid, &suid, &fsuid, vuht_get_private_data(ht));
		sd->ret_value = fsuid;
		if (new_fsuid != (uid_t ) -1)
			service_syscall(ht, __VU_setresfuid)(ruid, euid, suid, new_fsuid, vuht_get_private_data(ht));
		sd->action = SKIPIT;
	} else if (nested) {
		if (new_fsuid != (uid_t ) -1) {
			sd->ret_value = -ENOSYS;
			sd->action = SKIPIT;
		} else {
			uid_t ruid, euid, suid, fsuid;
			vu_uidgid_getresfuid(&ruid, &euid, &suid, &fsuid);
			sd->ret_value = fsuid;
		}
	} else { // !ht && !nested
		sd->action = DOIT_CB_AFTER;
	}
}

static void wi_setfsgid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	gid_t new_fsgid = sd->syscall_args[0];
	if (ht) {
		gid_t rgid, egid, sgid, fsgid;
		service_syscall(ht, __VU_getresfgid)(&rgid, &egid, &sgid, &fsgid, vuht_get_private_data(ht));
		sd->ret_value = fsgid;
		if (new_fsgid != (gid_t ) -1)
			service_syscall(ht, __VU_setresfgid)(rgid, egid, sgid, new_fsgid, vuht_get_private_data(ht));
		sd->action = SKIPIT;
	} else if (nested) {
		gid_t new_fsgid = sd->syscall_args[0];
		if (new_fsgid != (gid_t ) -1) {
			sd->ret_value = -ENOSYS;
			sd->action = SKIPIT;
		} else {
			gid_t rgid, egid, sgid, fsgid;
			vu_uidgid_getresfgid(&rgid, &egid, &sgid, &fsgid);
			sd->ret_value = fsgid;
		}
	} else { // !ht && !nested
		sd->action = DOIT_CB_AFTER;
	}
}

/* in this way modules can provide only setresfuid and setresfgid */

void wi_setresfuid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int syscall_number = sd->syscall_number;
	if (syscall_number == __NR_setfsuid)
		wi_setfsuid(ht, sd);
	else
		wi_setresuid(ht, sd);
}

void wi_setresfgid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int syscall_number = sd->syscall_number;
	if (syscall_number == __NR_setfsgid)
		wi_setfsgid(ht, sd);
	else
		wi_setresgid(ht, sd);
}

void wo_setresfuid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
	if (sd->ret_value == 0) {
		/* if the real system call succeeded, update vu_uidgid */
		int syscall_number = sd->syscall_number;
		uid_t ruid, euid, suid, fsuid, newfsuid;
		vu_uidgid_getresfuid(&ruid, &euid, &suid, &fsuid);
		switch (syscall_number) {
			case __NR_setuid:
				if (euid == 0)
					euid = ruid = suid = fsuid = sd->syscall_args[0];
				else
					euid = sd->syscall_args[0];
			break;
		case __NR_setreuid:
			ruid = sd->syscall_args[0];
			euid = sd->syscall_args[1];
			break;
		case __NR_setresuid:
			ruid = sd->syscall_args[0];
			euid = sd->syscall_args[1];
			suid = sd->syscall_args[2];
			break;
		case __NR_setfsuid:
			newfsuid = sd->syscall_args[0];
			if (euid == 0 || newfsuid == ruid || newfsuid == euid
					|| newfsuid == suid || newfsuid == fsuid)
				fsuid = newfsuid;
			break;
		}
		vu_uidgid_setresfuid(ruid, euid, suid, fsuid);
	}
}

void wo_setresfgid(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
  sd->ret_value = sd->orig_ret_value;
  if (sd->ret_value == 0) {
		/* if the real system call succeeded, update vu_uidgid */
		int syscall_number = sd->syscall_number;
		uid_t euid;
		gid_t rgid, egid, sgid, fsgid, newfsgid;
		vu_uidgid_getresfuid(NULL, &euid, NULL, NULL);
		vu_uidgid_getresfgid(&rgid, &egid, &sgid, &fsgid);
    switch (syscall_number) {
      case __NR_setgid:
        if (euid == 0)
          egid = rgid = sgid = fsgid = sd->syscall_args[0];
        else
          egid = sd->syscall_args[0];
      break;
    case __NR_setregid:
      rgid = sd->syscall_args[0];
      egid = sd->syscall_args[1];
      break;
    case __NR_setresgid:
      rgid = sd->syscall_args[0];
      egid = sd->syscall_args[1];
      sgid = sd->syscall_args[2];
      break;
    case __NR_setfsgid:
      newfsgid = sd->syscall_args[0];
      if (egid == 0 || newfsgid == rgid || newfsgid == egid
          || newfsgid == sgid || newfsgid == fsgid)
        fsgid = newfsgid;
      break;
    }
    vu_uidgid_setresfgid(rgid, egid, sgid, fsgid);
  }
}

void wi_setgroups(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	int nested = sd->extra->nested;
	if (ht) {
		int ret_value;
		int size = sd->syscall_args[0];
		uintptr_t listaddr =  sd->syscall_args[1];
		gid_t *list;
		vu_alloc_peek_arg(listaddr, list, size * sizeof(gid_t), nested);
		ret_value = service_syscall(ht, __VU_setgroups)(size, list, vuht_get_private_data(ht));
		vu_free_arg(list, nested);
		if (ret_value < 0)
			sd->ret_value = -errno;
		else
			sd->ret_value = ret_value;
	} else if (nested) {
		sd->ret_value = -ENOSYS;
    sd->action = SKIPIT;
	} else { // !ht && !nested
		sd->action = DOIT_CB_AFTER;
	}
}

void wo_setgroups(struct vuht_entry_t *ht, struct syscall_descriptor_t *sd) {
	sd->ret_value = sd->orig_ret_value;
	if (sd->ret_value == 0) {
		/* if the real system call succeeded, update vu_uidgid */
		int size = sd->syscall_args[0];
    uintptr_t listaddr =  sd->syscall_args[1];
    gid_t *list;
    vu_alloc_peek_arg(listaddr, list, size * sizeof(gid_t), VU_NOT_NESTED);
		vu_uidgid_setgroups(size, list);
		vu_free_arg(list, VU_NOT_NESTED);
	}
}

