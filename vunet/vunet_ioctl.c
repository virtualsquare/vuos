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

#include<sys/ioctl.h>
#include<asm/ioctl.h>
#include <linux/if.h>
#include <linux/sockios.h>

long vunet_ioctl_parms(unsigned long request) {
	switch (request) {
		case FIONREAD:
      return _IOW(' ', 0, int);
    case FIONBIO:
      return _IOR(' ', 0, int);
    case SIOCGIFCONF:
      return _IOWR(' ', 0, struct ifconf);
    case SIOCGSTAMP:
      return _IOW(' ', 0, struct timeval);
    case SIOCGIFNAME:
    case SIOCGIFFLAGS:
    case SIOCGIFADDR:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
    case SIOCGIFNETMASK:
    case SIOCGIFMETRIC:
    case SIOCGIFMEM:
    case SIOCGIFMTU:
    case SIOCGIFHWADDR:
    case SIOCGIFINDEX:
    case SIOCGIFTXQLEN:
      return _IOWR(' ', 0, struct ifreq);
    case SIOCSIFNAME:
    case SIOCSIFFLAGS:
    case SIOCSIFADDR:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
    case SIOCSIFNETMASK:
    case SIOCSIFMETRIC:
    case SIOCSIFMEM:
    case SIOCSIFMTU:
    case SIOCSIFHWADDR:
    case SIOCSIFTXQLEN:
    case SIOCSIFHWBROADCAST:
      return _IOR(' ', 0, struct ifreq);
    case SIOCGIFMAP:
      return _IOWR(' ', 0, struct ifmap);
    case SIOCSIFMAP:
      return _IOR(' ', 0, struct ifmap);
    default:
      return 0;
	}
}

int vunet_is_netdev_ioctl(unsigned long request) {
  switch (request) {
    case SIOCGIFCONF:
    case SIOCGSTAMP:
    case SIOCGIFNAME:
    case SIOCGIFFLAGS:
    case SIOCGIFADDR:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
    case SIOCGIFNETMASK:
    case SIOCGIFMETRIC:
    case SIOCGIFMEM:
    case SIOCGIFMTU:
    case SIOCGIFHWADDR:
    case SIOCGIFINDEX:
    case SIOCGIFTXQLEN:
    case SIOCSIFNAME:
    case SIOCSIFFLAGS:
    case SIOCSIFADDR:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
    case SIOCSIFNETMASK:
    case SIOCSIFMETRIC:
    case SIOCSIFMEM:
    case SIOCSIFMTU:
    case SIOCSIFHWADDR:
    case SIOCSIFTXQLEN:
    case SIOCSIFHWBROADCAST:
    case SIOCGIFMAP:
    case SIOCSIFMAP:
			return 1;
		default:
			return 0;
	}
}
