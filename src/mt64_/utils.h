#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>

size_t strstrmem(char *s1, size_t len, char *s2);
void erasefree(char *str);
char *savepasswd(char *path, char *passwd);
int openfile(char *path);
int search_line(int fd, char *str, int len);

#endif // UTILS_H_
