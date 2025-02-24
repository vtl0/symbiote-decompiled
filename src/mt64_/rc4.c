#include <string.h>

#include "rc4.h"

void *rc4(const char *key, char *buf, int len) {
  unsigned char s[256];
  char swap;
  unsigned char *decrypted_buf;
  int key_len;

  decrypted_buf = (unsigned char *)buf;
  key_len = strlen((char *)key);
  for (int i = 0; i < 256; i++)
    s[i] = i;
  for (int i = 0, j = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key_len]) % 256;
    swap = s[i];
    s[i] = s[j];
    s[j] = swap;
  }
  for (int i = 1, j = 0, k = 0; k < len; k++, i++) {
    i %= 256;
    j = (j + s[i]) % 256;
    swap = s[i];
    s[i] = s[j];
    s[j] = swap;
    decrypted_buf[k] ^= s[(unsigned char)(s[i] + s[j])];
  }
  return buf;
}
