/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon_runtime.h"
#include "../noxtls/noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#include "../client/version.h"

static void print_usage(const char * prog)
{
    fprintf(stderr,
            "%s " NOXSSH_VERSION_STRING " — NoxSSH server (sequential accept)\n"
            "Usage: %s [-b bind] [-p port] --password <pass> [--host-key <file>]\n"
            "  -b bind    Address to bind (default: all interfaces)\n"
            "  -p port    TCP port (default: 2222)\n"
            "  --password Password accepted for any username (required for password auth)\n"
            "  --host-key Path to 32-byte raw Ed25519 seed file (optional; ephemeral if omitted)\n",
            prog, prog);
}

int main(int argc, char ** argv)
{
    const char * bind_host = NULL;
    const char * password = NULL;
    const char * host_key_path = NULL;
    uint16_t port = 2222u;
    uint8_t host_seed[32];
    uint8_t host_pk[32];
    int i;

    for(i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if(strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bind_host = argv[++i];
        } else if(strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            int p = atoi(argv[++i]);
            if(p <= 0 || p > 65535) {
                fprintf(stderr, "noxsshd: invalid port\n");
                return 1;
            }
            port = (uint16_t)p;
        } else if(strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            password = argv[++i];
        } else if(strcmp(argv[i], "--host-key") == 0 && i + 1 < argc) {
            host_key_path = argv[++i];
        } else {
            fprintf(stderr, "noxsshd: unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if(password == NULL || password[0] == '\0') {
        fprintf(stderr, "noxsshd: --password is required\n");
        return 1;
    }

    if(host_key_path != NULL) {
        FILE * f = fopen(host_key_path, "rb");
        if(f == NULL) {
            perror("noxsshd: fopen host key");
            return 1;
        }
        if(fread(host_seed, 1u, sizeof(host_seed), f) != sizeof(host_seed)) {
            fprintf(stderr, "noxsshd: host key file must be exactly 32 bytes\n");
            fclose(f);
            return 1;
        }
        fclose(f);
    } else {
        if(noxtls_ed25519_generate_key(host_seed, host_pk) != NOXTLS_RETURN_SUCCESS) {
            fprintf(stderr, "noxsshd: failed to generate ephemeral host key\n");
            return 1;
        }
        (void)fprintf(stderr, "noxsshd: warning: ephemeral host key (not saved); clients will see host key warnings\n");
        (void)host_pk;
    }

    return noxsshd_listen_loop(bind_host, port, password, host_seed);
}
