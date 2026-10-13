#define _GNU_SOURCE
#include "auth_posix.h"
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static int b64val(unsigned char c)
{
    if(c >= 'A' && c <= 'Z') return c - 'A';
    if(c >= 'a' && c <= 'z') return c - 'a' + 26;
    if(c >= '0' && c <= '9') return c - '0' + 52;
    if(c == '+') return 62;
    if(c == '/') return 63;
    return -1;
}

static int decode_blob(const char *src, size_t len, uint8_t out[51])
{
    size_t i, n = 0;
    unsigned x;
    if(len != 68u) return 0; /* 51-byte ssh-ed25519 blob. */
    for(i = 0; i < len; i += 4u) {
        int a = b64val((unsigned char)src[i]);
        int b = b64val((unsigned char)src[i+1]);
        int c = b64val((unsigned char)src[i+2]);
        int d = b64val((unsigned char)src[i+3]);
        if(a < 0 || b < 0 || c < 0 || d < 0) return 0;
        x = ((unsigned)a << 18) | ((unsigned)b << 12) | ((unsigned)c << 6) | (unsigned)d;
        out[n++] = (uint8_t)(x >> 16);
        out[n++] = (uint8_t)(x >> 8);
        out[n++] = (uint8_t)x;
    }
    return n == 51u && memcmp(out, "\0\0\0\13ssh-ed25519\0\0\0\040", 19u) == 0;
}

static int authorized_user_key(const char * username, const uint8_t * key)
{
    struct passwd pwd, *pw = NULL;
    char pwbuf[16384], path[4096], line[8192];
    struct stat st;
    FILE *f;
    int fd, ok = 0;
    size_t home_len;
    if(!username || !username[0] || strchr(username, '/') || strchr(username, '\\') ||
       getpwnam_r(username, &pwd, pwbuf, sizeof(pwbuf), &pw) != 0 || !pw ||
       !pw->pw_dir || !pw->pw_dir[0] || !pw->pw_shell || !pw->pw_shell[0] ||
       strstr(pw->pw_shell, "nologin") || strstr(pw->pw_shell, "false")) return 0;
    home_len = strlen(pw->pw_dir);
    if(home_len + sizeof("/.ssh/authorized_keys") > sizeof(path)) return 0;
    if(stat(pw->pw_dir, &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 022) ||
       (st.st_uid != pw->pw_uid && st.st_uid != 0)) return 0;
    snprintf(path, sizeof(path), "%s/.ssh", pw->pw_dir);
    if(lstat(path, &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 022) ||
       (st.st_uid != pw->pw_uid && st.st_uid != 0)) return 0;
    snprintf(path, sizeof(path), "%s/.ssh/authorized_keys", pw->pw_dir);
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0) return 0;
    if(fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 022) ||
       st.st_size > 65536 || (st.st_uid != pw->pw_uid && st.st_uid != 0)) { close(fd); return 0; }
    f = fdopen(fd, "r");
    if(!f) { close(fd); return 0; }
    while(fgets(line, sizeof(line), f)) {
        char *alg = line, *blob;
        size_t len;
        uint8_t decoded[51];
        while(*alg == ' ' || *alg == '\t') alg++;
        if(strncmp(alg, "ssh-ed25519", 11u) != 0 || (alg[11] != ' ' && alg[11] != '\t')) continue;
        blob = alg + 11;
        while(*blob == ' ' || *blob == '\t') blob++;
        len = strcspn(blob, " \t\r\n");
        if(decode_blob(blob, len, decoded) && (!key || memcmp(decoded + 19, key, 32u) == 0)) { ok = 1; break; }
    }
    fclose(f);
    return ok;
}

int noxsshd_authorized_ed25519(void * unused, const char * username, const uint8_t key[32])
{
    (void)unused;
    return key ? authorized_user_key(username, key) : 0;
}

int noxsshd_authorized_user_ready(const char * username)
{
    return authorized_user_key(username, NULL);
}
