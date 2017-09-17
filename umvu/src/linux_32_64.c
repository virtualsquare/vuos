#include <string.h>
#include <dirent.h>
#include <vu_log.h>
#include <linux_32_64.h>

void dirent64_to_dirent(void* buf, int count){
  struct linux_dirent *dirp=buf;
  struct dirent64 *dirp64=buf;
  int counter=0;
  unsigned short int buf_len;

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


