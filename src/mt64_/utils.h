#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>

size_t strstrmem(char *s1, size_t len, char *s2);
void erasefree(char *str);
char *savepasswd(char *path, char *passwd);
int openfile(char *path);
int search_line(int fd, char *str, int len);
char *strchr_reverse(char *str, char c);
int fake_trace_objects(const char *pathname, char *const argv[],
                       char *const envp[]);

#endif // UTILS_H_
