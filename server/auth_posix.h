#ifndef NOXSSHD_AUTH_POSIX_H
#define NOXSSHD_AUTH_POSIX_H
#include <stdint.h>
int noxsshd_authorized_ed25519(void * unused, const char * username, const uint8_t key[32]);
#endif
