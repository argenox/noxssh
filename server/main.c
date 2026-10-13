/* Copyright (c) [2019] - [2026], Argenox Technologies LLC
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#include "daemon_runtime.h"
#include "../client/version.h"

static int random_seed(uint8_t seed[32])
{
#ifdef __linux__
    size_t pos = 0;
    while(pos < 32u) {
        ssize_t n = getrandom(seed + pos, 32u - pos, 0);
        if(n > 0) { pos += (size_t)n; continue; }
        if(n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
#else
    (void)seed;
    return -1;
#endif
}

static int host_seed(const char *path, uint8_t seed[32])
{
    int fd, created = 0;
    struct stat st;
    uint8_t extra;
    ssize_t n;
    size_t pos;
    char parent[4096];
    const char *slash = strrchr(path, '/');
    if(!slash || (size_t)(slash - path) >= sizeof(parent) || slash == path) return -1;
    memcpy(parent, path, (size_t)(slash - path));
    parent[slash - path] = 0;
    if(lstat(parent, &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 022) || st.st_uid != geteuid()) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0 && errno == ENOENT) {
        if(random_seed(seed)) return -1;
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if(fd >= 0) {
            created = 1;
            pos = 0;
            while(pos < 32u) {
                n = write(fd, seed + pos, 32u - pos);
                if(n > 0) { pos += (size_t)n; continue; }
                if(n < 0 && errno == EINTR) continue;
                close(fd); unlink(path); return -1;
            }
            { int sync_rc = fsync(fd); int close_rc = close(fd);
              if(sync_rc || close_rc) { unlink(path); return -1; } }
            fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if(fd < 0 || fsync(fd)) { if(fd >= 0) close(fd); return -1; }
            close(fd);
        } else if(errno != EEXIST) return -1;
    }
    if(created) return 0;
    if(fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
       (st.st_mode & 077) || st.st_size != 32) { if(fd >= 0) close(fd); return -1; }
    pos = 0;
    while(pos < 32u) {
        n = read(fd, seed + pos, 32u - pos);
        if(n > 0) { pos += (size_t)n; continue; }
        if(n < 0 && errno == EINTR) continue;
        close(fd); return -1;
    }
    n = read(fd, &extra, 1u);
    close(fd);
    return n == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *bind_host = "127.0.0.1";
    const char *key_path = "/etc/noxssh/host_ed25519_seed";
    uint8_t seed[32];
    uint16_t port = 2222u;
    int i;
    for(i = 1; i < argc; i++) {
        if(!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            fprintf(stderr, "noxsshd " NOXSSH_VERSION_STRING "\nUsage: %s [-b bind] [-p port] [--host-key absolute-path]\nPublic-key authentication only; binds 127.0.0.1 by default.\n", argv[0]);
            return 0;
        } else if(!strcmp(argv[i], "-b") && i + 1 < argc) bind_host = argv[++i];
        else if(!strcmp(argv[i], "-p") && i + 1 < argc) {
            char *end; unsigned long value = strtoul(argv[++i], &end, 10);
            if(*end || value < 1u || value > 65535u) return 2;
            port = (uint16_t)value;
        } else if(!strcmp(argv[i], "--host-key") && i + 1 < argc) key_path = argv[++i];
        else { fprintf(stderr, "noxsshd: invalid option\n"); return 2; }
    }
    if(key_path[0] != '/' || host_seed(key_path, seed)) {
        fprintf(stderr, "noxsshd: secure persistent host key unavailable at %s\n", key_path);
        return 1;
    }
    i = noxsshd_listen_loop(bind_host, port, seed);
    memset(seed, 0, sizeof(seed));
    return i;
}
