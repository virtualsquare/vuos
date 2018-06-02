#include<sys/ioctl.h>
#include<asm/ioctl.h>
#include <linux/if.h>

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
