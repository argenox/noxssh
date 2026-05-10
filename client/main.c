/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    main.c
* Summary: noxssh CLI application using SSH common protocol API
*
*/

/**
 * @file main.c
 * @brief noxssh CLI application using SSH common protocol API.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <direct.h>
typedef SOCKET app_socket_t;
#define APP_INVALID_SOCKET INVALID_SOCKET
#define APP_CLOSESOCK closesocket
#else
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
typedef int app_socket_t;
#define APP_INVALID_SOCKET (-1)
#define APP_CLOSESOCK close
#endif

#include "version.h"
#include "../noxtls/noxtls_version.h"
#include "noxssh_common.h"

/** @brief Default username when user@host is not provided. */
#define NOXSSH_DEFAULT_USER "user"
/** @brief Max hostname length accepted by CLI parser. */
#define NOXSSH_MAX_HOST_LEN NETNOX_SSH_MAX_HOST_LEN
/** @brief Max username length accepted by CLI parser. */
#define NOXSSH_MAX_USER_LEN NETNOX_SSH_MAX_USERNAME_LEN
/** @brief Max command length accepted by CLI parser. */
#define NOXSSH_MAX_COMMAND_LEN NETNOX_SSH_MAX_COMMAND_LEN
/** @brief Max password length accepted by CLI parser. */
#define NOXSSH_MAX_PASSWORD_LEN NETNOX_SSH_MAX_PASSWORD_LEN
/** @brief Max path length for known_hosts path assembly. */
#define NOXSSH_MAX_PATH_LEN (1024u)
/** @brief Expected hex length for SHA-256 fingerprint text. */
#define NOXSSH_HOSTKEY_HEX_LEN (NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN * 2u)
/** @brief Expected hex length for Ed25519 32-byte private key seed. */
#define NOXSSH_ED25519_KEY_HEX_LEN (64u)
/** @brief Max line size accepted when parsing ~/.ssh/config. */
#define NOXSSH_SSHCFG_MAX_LINE_LEN (1024u)
/** @brief Identity loader status: success. */
#define NOXSSH_KEY_LOAD_SUCCESS (0)
/** @brief Identity loader status: generic failure. */
#define NOXSSH_KEY_LOAD_FAILED (-1)
/** @brief Identity loader status: encrypted key unsupported. */
#define NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED (-2)
/** @brief StrictHostKeyChecking mode: ask user (default). */
#define NOXSSH_HOSTKEY_CHECK_ASK (0)
/** @brief StrictHostKeyChecking mode: reject unknown hosts. */
#define NOXSSH_HOSTKEY_CHECK_YES (1)
/** @brief StrictHostKeyChecking mode: accept even unknown/changed host keys. */
#define NOXSSH_HOSTKEY_CHECK_NO (2)
/** @brief StrictHostKeyChecking mode: auto-trust unknown, reject changed. */
#define NOXSSH_HOSTKEY_CHECK_ACCEPT_NEW (3)

/** Application socket context passed to netnox_ssh transport callbacks. */
typedef struct
{
    app_socket_t sock;
} noxssh_conn_t;

typedef struct
{
    char host_name[NOXSSH_MAX_HOST_LEN + 1u];
    char user[NOXSSH_MAX_USER_LEN + 1u];
    char identity_file[NOXSSH_MAX_PATH_LEN];
    char user_known_hosts_file[NOXSSH_MAX_PATH_LEN];
    uint16_t port;
    int has_host_name;
    int has_user;
    int has_identity_file;
    int has_user_known_hosts_file;
    int has_port;
    int has_strict_host_key_checking;
    int strict_host_key_checking;
    int has_batch_mode;
    int batch_mode;
    int has_connect_timeout_ms;
    uint32_t connect_timeout_ms;
    int has_server_alive_interval_sec;
    uint32_t server_alive_interval_sec;
    int has_server_alive_count_max;
    uint32_t server_alive_count_max;
    int has_rekey_interval_sec;
    uint32_t rekey_interval_sec;
} noxssh_ssh_config_t;

/**
 * @brief Convert bytes to lowercase hex string.
 * @internal
 */
static void noxssh_bytes_to_hex(const uint8_t * in, uint32_t in_len, char * out, uint32_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    uint32_t i = 0u;

    if(in == NULL || out == NULL || out_len == 0u || out_len < (in_len * 2u + 1u)) {
        return;
    }
    for(i = 0u; i < in_len; i++) {
        out[i * 2u] = hex[(in[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = hex[in[i] & 0x0Fu];
    }
    out[in_len * 2u] = '\0';
}

/**
 * @brief Parse one ASCII hex nibble to integer value.
 * @internal
 */
static int noxssh_hex_nibble(char c)
{
    if(c >= '0' && c <= '9') {
        return (int)(c - '0');
    }
    if(c >= 'a' && c <= 'f') {
        return (int)(c - 'a' + 10);
    }
    if(c >= 'A' && c <= 'F') {
        return (int)(c - 'A' + 10);
    }
    return -1;
}

/**
 * @brief Decode fixed-length hex string to bytes.
 * @internal
 */
static int noxssh_hex_to_bytes(const char * hex, uint8_t * out, uint32_t out_len)
{
    uint32_t i = 0u;
    int hi = 0;
    int lo = 0;

    if(hex == NULL || out == NULL || strlen(hex) != (size_t)(out_len * 2u)) {
        return -1;
    }
    for(i = 0u; i < out_len; i++) {
        hi = noxssh_hex_nibble(hex[i * 2u]);
        lo = noxssh_hex_nibble(hex[i * 2u + 1u]);
        if(hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/**
 * @brief Base64 decode one character.
 * @internal
 */
static int noxssh_base64_val(char c)
{
    if(c >= 'A' && c <= 'Z') {
        return (int)(c - 'A');
    }
    if(c >= 'a' && c <= 'z') {
        return (int)(c - 'a' + 26);
    }
    if(c >= '0' && c <= '9') {
        return (int)(c - '0' + 52);
    }
    if(c == '+') {
        return 62;
    }
    if(c == '/') {
        return 63;
    }
    return -1;
}

/**
 * @brief Decode base64 payload into bytes.
 * @internal
 */
static int noxssh_base64_decode(const char * in, uint32_t in_len, uint8_t * out, uint32_t out_max, uint32_t * out_len)
{
    uint32_t i = 0u;
    uint32_t o = 0u;
    int v0 = 0;
    int v1 = 0;
    int v2 = 0;
    int v3 = 0;
    char c0 = 0;
    char c1 = 0;
    char c2 = 0;
    char c3 = 0;

    if(in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if((in_len % 4u) != 0u) {
        return -1;
    }
    for(i = 0u; i < in_len; i += 4u) {
        c0 = in[i];
        c1 = in[i + 1u];
        c2 = in[i + 2u];
        c3 = in[i + 3u];
        v0 = noxssh_base64_val(c0);
        v1 = noxssh_base64_val(c1);
        if(v0 < 0 || v1 < 0) {
            return -1;
        }
        v2 = (c2 == '=') ? -1 : noxssh_base64_val(c2);
        v3 = (c3 == '=') ? -1 : noxssh_base64_val(c3);
        if(v2 < -1 || v3 < -1 || (v2 < 0 && c2 != '=') || (v3 < 0 && c3 != '=')) {
            return -1;
        }

        if(o + 1u > out_max) {
            return -1;
        }
        out[o++] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if(c2 != '=') {
            if(o + 1u > out_max) {
                return -1;
            }
            out[o++] = (uint8_t)(((v1 & 0x0F) << 4) | (v2 >> 2));
        }
        if(c3 != '=') {
            if(o + 1u > out_max) {
                return -1;
            }
            out[o++] = (uint8_t)(((v2 & 0x03) << 6) | v3);
        }
    }
    *out_len = o;
    return 0;
}

static uint32_t noxssh_read_u32_be(const uint8_t * p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int noxssh_read_ssh_string_view(const uint8_t * buf,
                                       uint32_t buf_len,
                                       uint32_t * offset,
                                       const uint8_t ** out_ptr,
                                       uint32_t * out_len)
{
    uint32_t len = 0u;
    if(buf == NULL || offset == NULL || out_ptr == NULL || out_len == NULL) {
        return -1;
    }
    if(*offset + 4u > buf_len) {
        return -1;
    }
    len = noxssh_read_u32_be(&buf[*offset]);
    *offset += 4u;
    if(*offset + len > buf_len) {
        return -1;
    }
    *out_ptr = &buf[*offset];
    *out_len = len;
    *offset += len;
    return 0;
}

/**
 * @brief Try loading unencrypted OpenSSH Ed25519 private key.
 * @internal
 */
static int noxssh_load_openssh_ed25519_key(const char * text, uint32_t text_len, uint8_t out_seed[32])
{
    static const char begin_marker[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static const char end_marker[] = "-----END OPENSSH PRIVATE KEY-----";
    static const char auth_magic[] = "openssh-key-v1\0";
    static const char keytype_ed25519[] = "ssh-ed25519";
    const char * begin = NULL;
    const char * end = NULL;
    char b64[8192];
    uint32_t b64_len = 0u;
    uint8_t decoded[8192];
    uint32_t decoded_len = 0u;
    uint32_t off = 0u;
    const uint8_t * s = NULL;
    uint32_t s_len = 0u;
    uint32_t nkeys = 0u;
    uint32_t i = 0u;
    const uint8_t * priv_blob = NULL;
    uint32_t priv_blob_len = 0u;
    uint32_t poff = 0u;
    uint32_t check1 = 0u;
    uint32_t check2 = 0u;
    const uint8_t * keytype = NULL;
    uint32_t keytype_len = 0u;
    const uint8_t * pub = NULL;
    uint32_t pub_len = 0u;
    const uint8_t * priv = NULL;
    uint32_t priv_len = 0u;

    if(text == NULL || out_seed == NULL) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    begin = strstr(text, begin_marker);
    if(begin == NULL) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    begin += strlen(begin_marker);
    end = strstr(begin, end_marker);
    if(end == NULL || end <= begin) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    for(i = 0u; i < (uint32_t)(end - begin); i++) {
        char c = begin[i];
        if((c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=') {
            if(b64_len + 1u >= (uint32_t)sizeof(b64)) {
                return NOXSSH_KEY_LOAD_FAILED;
            }
            b64[b64_len++] = c;
        }
    }
    if(b64_len == 0u || noxssh_base64_decode(b64, b64_len, decoded, (uint32_t)sizeof(decoded), &decoded_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(decoded_len < (uint32_t)sizeof(auth_magic) - 1u ||
       memcmp(decoded, auth_magic, sizeof(auth_magic) - 1u) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    off = (uint32_t)sizeof(auth_magic) - 1u;

    /* ciphername */
    if(noxssh_read_ssh_string_view(decoded, decoded_len, &off, &s, &s_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(!(s_len == 4u && memcmp(s, "none", 4u) == 0)) {
        return NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED;
    }
    /* kdfname */
    if(noxssh_read_ssh_string_view(decoded, decoded_len, &off, &s, &s_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(!(s_len == 4u && memcmp(s, "none", 4u) == 0)) {
        return NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED;
    }
    /* kdfoptions */
    if(noxssh_read_ssh_string_view(decoded, decoded_len, &off, &s, &s_len) != 0 || s_len != 0u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(off + 4u > decoded_len) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    nkeys = noxssh_read_u32_be(&decoded[off]);
    off += 4u;
    if(nkeys == 0u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    for(i = 0u; i < nkeys; i++) {
        if(noxssh_read_ssh_string_view(decoded, decoded_len, &off, &s, &s_len) != 0) {
            return NOXSSH_KEY_LOAD_FAILED;
        }
    }
    if(noxssh_read_ssh_string_view(decoded, decoded_len, &off, &priv_blob, &priv_blob_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }

    if(priv_blob_len < 8u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    check1 = noxssh_read_u32_be(priv_blob);
    check2 = noxssh_read_u32_be(priv_blob + 4u);
    if(check1 != check2) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    poff = 8u;
    if(noxssh_read_ssh_string_view(priv_blob, priv_blob_len, &poff, &keytype, &keytype_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(keytype_len != (uint32_t)strlen(keytype_ed25519) ||
       memcmp(keytype, keytype_ed25519, keytype_len) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(noxssh_read_ssh_string_view(priv_blob, priv_blob_len, &poff, &pub, &pub_len) != 0 || pub_len != 32u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(noxssh_read_ssh_string_view(priv_blob, priv_blob_len, &poff, &priv, &priv_len) != 0 || priv_len != 64u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    if(memcmp(&priv[32], pub, 32u) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    memcpy(out_seed, priv, 32u);
    return NOXSSH_KEY_LOAD_SUCCESS;
}

/**
 * @brief Load Ed25519 private key seed from identity file.
 * @internal
 *
 * Expected content: 64 hex characters (whitespace is ignored).
 */
static int noxssh_load_ed25519_seed_file(const char * path, uint8_t out_seed[32])
{
    FILE * f = NULL;
    char raw[4096];
    size_t nread = 0u;
    char hex[NOXSSH_ED25519_KEY_HEX_LEN + 1u];
    uint32_t hex_len = 0u;
    uint32_t i = 0u;

    if(path == NULL || out_seed == NULL) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    f = fopen(path, "rb");
    if(f == NULL) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    nread = fread(raw, 1u, sizeof(raw) - 1u, f);
    (void)fclose(f);
    if(nread == 0u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    raw[nread] = '\0';

    for(i = 0u; i < (uint32_t)nread; i++) {
        int nib = noxssh_hex_nibble(raw[i]);
        if(nib >= 0) {
            if(hex_len >= NOXSSH_ED25519_KEY_HEX_LEN) {
                return -1;
            }
            hex[hex_len++] = raw[i];
        } else if(raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\r' || raw[i] == '\n') {
            continue;
        } else {
            /* Ignore non-hex decoration to allow basic "seed: <hex>" wrappers. */
            continue;
        }
    }
    if(hex_len == NOXSSH_ED25519_KEY_HEX_LEN) {
        hex[hex_len] = '\0';
        if(noxssh_hex_to_bytes(hex, out_seed, 32u) == 0) {
            return NOXSSH_KEY_LOAD_SUCCESS;
        }
        return NOXSSH_KEY_LOAD_FAILED;
    }
    return noxssh_load_openssh_ed25519_key(raw, (uint32_t)nread, out_seed);
}

static void noxssh_sleep_ms(uint32_t ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    (void)usleep((useconds_t)(ms * 1000u));
#endif
}

static uint64_t noxssh_now_seconds(void)
{
    return (uint64_t)time(NULL);
}

static int noxssh_maybe_rekey(netnox_ssh_client_t * client,
                              uint32_t rekey_interval_sec,
                              uint64_t * last_rekey_sec)
{
    uint64_t now_sec = 0u;

    if(client == NULL) {
        return -1;
    }
    if(rekey_interval_sec == 0u || last_rekey_sec == NULL) {
        return 0;
    }
    now_sec = noxssh_now_seconds();
    if(now_sec < (*last_rekey_sec + (uint64_t)rekey_interval_sec)) {
        return 0;
    }
    if(netnox_ssh_client_rekey(client) != NETNOX_RETURN_SUCCESS) {
        return -1;
    }
    *last_rekey_sec = now_sec;
    return 1;
}

static int noxssh_socket_set_blocking(app_socket_t sock, int blocking)
{
#ifdef _WIN32
    u_long mode = (blocking != 0) ? 0ul : 1ul;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0) ? 0 : -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if(flags < 0) {
        return -1;
    }
    if(blocking != 0) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return (fcntl(sock, F_SETFL, flags) == 0) ? 0 : -1;
#endif
}

static int noxssh_connect_with_timeout(app_socket_t sock,
                                       const struct sockaddr * addr,
                                       int addrlen,
                                       uint32_t timeout_ms)
{
    int rc = 0;
    int sel = 0;
    int so_error = 0;
    fd_set wfds;
    fd_set efds;
    struct timeval tv;
#ifdef _WIN32
    int so_len = (int)sizeof(so_error);
#else
    socklen_t so_len = (socklen_t)sizeof(so_error);
#endif

    if(timeout_ms == 0u) {
        return (connect(sock, addr, addrlen) == 0) ? 0 : -1;
    }
    if(noxssh_socket_set_blocking(sock, 0) != 0) {
        return -1;
    }
    rc = connect(sock, addr, addrlen);
    if(rc == 0) {
        (void)noxssh_socket_set_blocking(sock, 1);
        return 0;
    }
#ifdef _WIN32
    if(WSAGetLastError() != WSAEWOULDBLOCK) {
        (void)noxssh_socket_set_blocking(sock, 1);
        return -1;
    }
#else
    if(errno != EINPROGRESS) {
        (void)noxssh_socket_set_blocking(sock, 1);
        return -1;
    }
#endif

    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(sock, &wfds);
    FD_SET(sock, &efds);
    tv.tv_sec = (long)(timeout_ms / 1000u);
    tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
#ifdef _WIN32
    sel = (int)select(0, NULL, &wfds, &efds, &tv);
#else
    sel = (int)select(sock + 1, NULL, &wfds, &efds, &tv);
#endif
    if(sel <= 0) {
        (void)noxssh_socket_set_blocking(sock, 1);
        return -1;
    }
    if(getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_len) != 0 || so_error != 0) {
        (void)noxssh_socket_set_blocking(sock, 1);
        return -1;
    }
    if(noxssh_socket_set_blocking(sock, 1) != 0) {
        return -1;
    }
    return 0;
}

static int noxssh_set_socket_io_timeout(app_socket_t sock, uint32_t timeout_ms)
{
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, (int)sizeof(tv)) != 0) {
        return -1;
    }
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, (int)sizeof(tv)) != 0) {
        return -1;
    }
#else
    struct timeval tv;
    tv.tv_sec = (long)(timeout_ms / 1000u);
    tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv)) != 0) {
        return -1;
    }
    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, (socklen_t)sizeof(tv)) != 0) {
        return -1;
    }
#endif
    return 0;
}

static int noxssh_get_home_dir(char * out_home, uint32_t out_home_len)
{
    const char * home = NULL;
    int n = 0;
    if(out_home == NULL || out_home_len == 0u) {
        return -1;
    }
#ifdef _WIN32
    home = getenv("USERPROFILE");
    if(home == NULL || home[0] == '\0') {
        const char * drive = getenv("HOMEDRIVE");
        const char * homepath = getenv("HOMEPATH");
        if(drive != NULL && homepath != NULL && drive[0] != '\0' && homepath[0] != '\0') {
            n = snprintf(out_home, out_home_len, "%s%s", drive, homepath);
            if(n > 0 && (uint32_t)n < out_home_len) {
                return 0;
            }
        }
        return -1;
    }
    n = snprintf(out_home, out_home_len, "%s", home);
#else
    home = getenv("HOME");
    if(home == NULL || home[0] == '\0') {
        return -1;
    }
    n = snprintf(out_home, out_home_len, "%s", home);
#endif
    if(n <= 0 || (uint32_t)n >= out_home_len) {
        return -1;
    }
    return 0;
}

static int noxssh_ascii_equals_ignore_case(const char * a, const char * b)
{
    uint32_t i = 0u;
    if(a == NULL || b == NULL) {
        return 0;
    }
    while(a[i] != '\0' && b[i] != '\0') {
        if(tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
        i++;
    }
    return (a[i] == '\0' && b[i] == '\0') ? 1 : 0;
}

static int noxssh_parse_strict_host_key_mode(const char * value, int * out_mode)
{
    if(value == NULL || out_mode == NULL) {
        return -1;
    }
    if(noxssh_ascii_equals_ignore_case(value, "yes") != 0 ||
       noxssh_ascii_equals_ignore_case(value, "true") != 0) {
        *out_mode = NOXSSH_HOSTKEY_CHECK_YES;
        return 0;
    }
    if(noxssh_ascii_equals_ignore_case(value, "no") != 0 ||
       noxssh_ascii_equals_ignore_case(value, "off") != 0 ||
       noxssh_ascii_equals_ignore_case(value, "false") != 0) {
        *out_mode = NOXSSH_HOSTKEY_CHECK_NO;
        return 0;
    }
    if(noxssh_ascii_equals_ignore_case(value, "accept-new") != 0) {
        *out_mode = NOXSSH_HOSTKEY_CHECK_ACCEPT_NEW;
        return 0;
    }
    if(noxssh_ascii_equals_ignore_case(value, "ask") != 0) {
        *out_mode = NOXSSH_HOSTKEY_CHECK_ASK;
        return 0;
    }
    return -1;
}

static char * noxssh_ltrim(char * s)
{
    if(s == NULL) {
        return NULL;
    }
    while(*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

static void noxssh_rtrim(char * s)
{
    size_t len = 0u;
    if(s == NULL) {
        return;
    }
    len = strlen(s);
    while(len > 0u && isspace((unsigned char)s[len - 1u])) {
        s[--len] = '\0';
    }
}

static int noxssh_host_pattern_match(const char * pattern, const char * host)
{
    if(pattern == NULL || host == NULL) {
        return 0;
    }
    if(*pattern == '\0') {
        return (*host == '\0') ? 1 : 0;
    }
    if(*pattern == '*') {
        do {
            if(noxssh_host_pattern_match(pattern + 1, host) != 0) {
                return 1;
            }
        } while(*host++ != '\0');
        return 0;
    }
    if(*pattern == '?') {
        return (*host == '\0') ? 0 : noxssh_host_pattern_match(pattern + 1, host + 1);
    }
    if(tolower((unsigned char)*pattern) != tolower((unsigned char)*host)) {
        return 0;
    }
    return noxssh_host_pattern_match(pattern + 1, host + 1);
}

static int noxssh_host_list_matches(const char * patterns, const char * host)
{
    char buf[NOXSSH_SSHCFG_MAX_LINE_LEN];
    char * token = NULL;
    int matched = 0;
    int has_positive = 0;

    if(patterns == NULL || host == NULL) {
        return 0;
    }
    strncpy(buf, patterns, sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = '\0';
    token = strtok(buf, " \t");
    while(token != NULL) {
        int negate = 0;
        if(token[0] == '!') {
            negate = 1;
            token++;
        }
        if(token[0] != '\0') {
            if(negate == 0) {
                has_positive = 1;
            }
            if(noxssh_host_pattern_match(token, host) != 0) {
                if(negate != 0) {
                    return 0;
                }
                matched = 1;
            }
        }
        token = strtok(NULL, " \t");
    }
    if(has_positive == 0) {
        return 0;
    }
    return matched;
}

static void noxssh_expand_home_path(const char * in_path, char * out_path, uint32_t out_len)
{
    char home[NOXSSH_MAX_PATH_LEN];
    int n = 0;
    if(in_path == NULL || out_path == NULL || out_len == 0u) {
        return;
    }
    if(in_path[0] == '~' && (in_path[1] == '/' || in_path[1] == '\\')) {
        if(noxssh_get_home_dir(home, (uint32_t)sizeof(home)) == 0) {
            n = snprintf(out_path, out_len, "%s%s", home, &in_path[1]);
            if(n > 0 && (uint32_t)n < out_len) {
                return;
            }
        }
    }
    strncpy(out_path, in_path, out_len - 1u);
    out_path[out_len - 1u] = '\0';
}

static int noxssh_load_ssh_config_for_host(const char * host_alias, noxssh_ssh_config_t * cfg)
{
    char home[NOXSSH_MAX_PATH_LEN];
    char path[NOXSSH_MAX_PATH_LEN];
    FILE * f = NULL;
    char line[NOXSSH_SSHCFG_MAX_LINE_LEN];
    int active_block = 0;

    if(host_alias == NULL || cfg == NULL) {
        return -1;
    }
    memset(cfg, 0, sizeof(*cfg));
    if(noxssh_get_home_dir(home, (uint32_t)sizeof(home)) != 0) {
        return -1;
    }
#ifdef _WIN32
    if(snprintf(path, sizeof(path), "%s\\.ssh\\config", home) <= 0) {
        return -1;
    }
#else
    if(snprintf(path, sizeof(path), "%s/.ssh/config", home) <= 0) {
        return -1;
    }
#endif
    f = fopen(path, "r");
    if(f == NULL) {
        return -1;
    }
    while(fgets(line, sizeof(line), f) != NULL) {
        char * p = noxssh_ltrim(line);
        char * key = NULL;
        char * value = NULL;
        char * sep = NULL;
        noxssh_rtrim(p);
        if(*p == '\0' || *p == '#') {
            continue;
        }
        sep = strpbrk(p, " \t=");
        if(sep == NULL) {
            continue;
        }
        *sep = '\0';
        key = p;
        value = noxssh_ltrim(sep + 1);
        noxssh_rtrim(value);
        if(*value == '\0') {
            continue;
        }

        if(noxssh_ascii_equals_ignore_case(key, "Host")) {
            active_block = noxssh_host_list_matches(value, host_alias);
            continue;
        }
        if(active_block == 0) {
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "HostName")) {
            if(cfg->has_host_name == 0) {
                strncpy(cfg->host_name, value, NOXSSH_MAX_HOST_LEN);
                cfg->host_name[NOXSSH_MAX_HOST_LEN] = '\0';
                cfg->has_host_name = 1;
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "User")) {
            if(cfg->has_user == 0) {
                strncpy(cfg->user, value, NOXSSH_MAX_USER_LEN);
                cfg->user[NOXSSH_MAX_USER_LEN] = '\0';
                cfg->has_user = 1;
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "Port")) {
            if(cfg->has_port == 0) {
                char * end_ptr = NULL;
                unsigned long parsed = strtoul(value, &end_ptr, 10);
                if(end_ptr != value && *end_ptr == '\0' && parsed > 0ul && parsed <= 65535ul) {
                    cfg->port = (uint16_t)parsed;
                    cfg->has_port = 1;
                }
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "IdentityFile")) {
            if(cfg->has_identity_file == 0) {
                noxssh_expand_home_path(value, cfg->identity_file, (uint32_t)sizeof(cfg->identity_file));
                cfg->has_identity_file = 1;
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "UserKnownHostsFile")) {
            if(cfg->has_user_known_hosts_file == 0) {
                noxssh_expand_home_path(value, cfg->user_known_hosts_file, (uint32_t)sizeof(cfg->user_known_hosts_file));
                cfg->has_user_known_hosts_file = 1;
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "StrictHostKeyChecking")) {
            if(cfg->has_strict_host_key_checking == 0) {
                if(noxssh_parse_strict_host_key_mode(value, &cfg->strict_host_key_checking) == 0) {
                    cfg->has_strict_host_key_checking = 1;
                }
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "BatchMode")) {
            if(cfg->has_batch_mode == 0) {
                cfg->has_batch_mode = 1;
                cfg->batch_mode = (noxssh_ascii_equals_ignore_case(value, "yes") != 0) ? 1 : 0;
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "ConnectTimeout")) {
            if(cfg->has_connect_timeout_ms == 0) {
                char * end_ptr = NULL;
                unsigned long parsed = strtoul(value, &end_ptr, 10);
                if(end_ptr != value && *end_ptr == '\0' && parsed <= 600ul) {
                    cfg->connect_timeout_ms = (uint32_t)parsed * 1000u;
                    cfg->has_connect_timeout_ms = 1;
                }
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "ServerAliveInterval")) {
            if(cfg->has_server_alive_interval_sec == 0) {
                char * end_ptr = NULL;
                unsigned long parsed = strtoul(value, &end_ptr, 10);
                if(end_ptr != value && *end_ptr == '\0' && parsed <= 3600ul) {
                    cfg->server_alive_interval_sec = (uint32_t)parsed;
                    cfg->has_server_alive_interval_sec = 1;
                }
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "ServerAliveCountMax")) {
            if(cfg->has_server_alive_count_max == 0) {
                char * end_ptr = NULL;
                unsigned long parsed = strtoul(value, &end_ptr, 10);
                if(end_ptr != value && *end_ptr == '\0' && parsed <= 100ul) {
                    cfg->server_alive_count_max = (uint32_t)parsed;
                    cfg->has_server_alive_count_max = 1;
                }
            }
            continue;
        }
        if(noxssh_ascii_equals_ignore_case(key, "RekeyInterval")) {
            if(cfg->has_rekey_interval_sec == 0) {
                char * end_ptr = NULL;
                unsigned long parsed = strtoul(value, &end_ptr, 10);
                if(end_ptr != value && *end_ptr == '\0' && parsed <= 86400ul) {
                    cfg->rekey_interval_sec = (uint32_t)parsed;
                    cfg->has_rekey_interval_sec = 1;
                }
            }
            continue;
        }
    }
    (void)fclose(f);
    return 0;
}

static int noxssh_try_load_default_identity(uint8_t out_seed[32],
                                            char * out_path,
                                            uint32_t out_path_len)
{
    char home[NOXSSH_MAX_PATH_LEN];
    char candidate[NOXSSH_MAX_PATH_LEN];
    int rc = NOXSSH_KEY_LOAD_FAILED;
    int n = 0;
    int i = 0;
    const char * rels[] = {
#ifdef _WIN32
        "\\.ssh\\id_ed25519",
        "\\.ssh\\id_ed25519.seed",
        "\\.noxssh\\id_ed25519.seed"
#else
        "/.ssh/id_ed25519",
        "/.ssh/id_ed25519.seed",
        "/.noxssh/id_ed25519.seed"
#endif
    };

    if(out_seed == NULL || out_path == NULL || out_path_len == 0u) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    out_path[0] = '\0';
    if(noxssh_get_home_dir(home, (uint32_t)sizeof(home)) != 0) {
        return NOXSSH_KEY_LOAD_FAILED;
    }
    for(i = 0; i < (int)(sizeof(rels) / sizeof(rels[0])); i++) {
        n = snprintf(candidate, sizeof(candidate), "%s%s", home, rels[i]);
        if(n <= 0 || (uint32_t)n >= (uint32_t)sizeof(candidate)) {
            continue;
        }
        rc = noxssh_load_ed25519_seed_file(candidate, out_seed);
        if(rc == NOXSSH_KEY_LOAD_SUCCESS) {
            strncpy(out_path, candidate, out_path_len - 1u);
            out_path[out_path_len - 1u] = '\0';
            return NOXSSH_KEY_LOAD_SUCCESS;
        }
        if(rc == NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED) {
            strncpy(out_path, candidate, out_path_len - 1u);
            out_path[out_path_len - 1u] = '\0';
            return NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED;
        }
    }
    return NOXSSH_KEY_LOAD_FAILED;
}

/**
 * @brief Validate lower/upper hex fingerprint text.
 * @internal
 */
static int noxssh_is_valid_hex_fingerprint(const char * s)
{
    uint32_t i = 0u;
    if(s == NULL || strlen(s) != NOXSSH_HOSTKEY_HEX_LEN) {
        return 0;
    }
    for(i = 0u; i < NOXSSH_HOSTKEY_HEX_LEN; i++) {
        if(!((s[i] >= '0' && s[i] <= '9') ||
             (s[i] >= 'a' && s[i] <= 'f') ||
             (s[i] >= 'A' && s[i] <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Convert ASCII hex string to lowercase in-place.
 * @internal
 */
static void noxssh_ascii_tolower_inplace(char * s)
{
    uint32_t i = 0u;
    if(s == NULL) {
        return;
    }
    for(i = 0u; s[i] != '\0'; i++) {
        if(s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = (char)(s[i] - 'A' + 'a');
        }
    }
}

/**
 * @brief Build per-user known_hosts path.
 * @internal
 */
static int noxssh_get_known_hosts_path(char * out_path, uint32_t out_path_len)
{
    const char * home = NULL;
    int n = 0;

    if(out_path == NULL || out_path_len == 0u) {
        return -1;
    }
#ifdef _WIN32
    home = getenv("USERPROFILE");
    if(home == NULL || home[0] == '\0') {
        const char * drive = getenv("HOMEDRIVE");
        const char * homepath = getenv("HOMEPATH");
        static char home_buf[NOXSSH_MAX_PATH_LEN];
        if(drive != NULL && homepath != NULL && drive[0] != '\0' && homepath[0] != '\0') {
            n = snprintf(home_buf, sizeof(home_buf), "%s%s", drive, homepath);
            if(n > 0 && (uint32_t)n < (uint32_t)sizeof(home_buf)) {
                home = home_buf;
            }
        }
    }
    if(home == NULL || home[0] == '\0') {
        return -1;
    }
    n = snprintf(out_path, out_path_len, "%s\\.noxssh\\known_hosts", home);
#else
    home = getenv("HOME");
    if(home == NULL || home[0] == '\0') {
        return -1;
    }
    n = snprintf(out_path, out_path_len, "%s/.noxssh/known_hosts", home);
#endif
    if(n <= 0 || (uint32_t)n >= out_path_len) {
        return -1;
    }
    return 0;
}

/**
 * @brief Ensure parent directory for known_hosts exists.
 * @internal
 */
static int noxssh_ensure_known_hosts_dir(const char * known_hosts_path)
{
    char dir_path[NOXSSH_MAX_PATH_LEN];
    char * sep = NULL;

    if(known_hosts_path == NULL || known_hosts_path[0] == '\0') {
        return -1;
    }
    strncpy(dir_path, known_hosts_path, sizeof(dir_path) - 1u);
    dir_path[sizeof(dir_path) - 1u] = '\0';
    sep = strrchr(dir_path, '/');
#ifdef _WIN32
    {
        char * sep2 = strrchr(dir_path, '\\');
        if(sep2 != NULL && (sep == NULL || sep2 > sep)) {
            sep = sep2;
        }
    }
#endif
    if(sep == NULL) {
        return -1;
    }
    *sep = '\0';
    if(dir_path[0] == '\0') {
        return -1;
    }
#ifdef _WIN32
    if(_mkdir(dir_path) != 0 && errno != EEXIST) {
        return -1;
    }
#else
    if(mkdir(dir_path, (mode_t)0700) != 0 && errno != EEXIST) {
        return -1;
    }
#endif
    return 0;
}

/**
 * @brief Lookup host fingerprint in known_hosts.
 * @internal
 *
 * @return 1 when found and copied, 0 when not found, -1 on parse/read error.
 */
static int noxssh_lookup_known_host(const char * known_hosts_path,
                                    const char * host,
                                    uint16_t port,
                                    char * out_hex,
                                    uint32_t out_hex_len)
{
    FILE * f = NULL;
    char line[1400];
    char file_host[NOXSSH_MAX_HOST_LEN + 1u];
    unsigned int file_port = 0u;
    char file_hex[NOXSSH_HOSTKEY_HEX_LEN + 1u];

    if(known_hosts_path == NULL || host == NULL || out_hex == NULL || out_hex_len == 0u) {
        return -1;
    }
    f = fopen(known_hosts_path, "r");
    if(f == NULL) {
        return 0;
    }
    while(fgets(line, sizeof(line), f) != NULL) {
        if(line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        if(sscanf(line, "%255s %u %64s", file_host, &file_port, file_hex) != 3) {
            continue;
        }
        if(strcmp(file_host, host) == 0 && file_port == (unsigned int)port) {
            strncpy(out_hex, file_hex, out_hex_len - 1u);
            out_hex[out_hex_len - 1u] = '\0';
            (void)fclose(f);
            return 1;
        }
    }
    (void)fclose(f);
    return 0;
}

/**
 * @brief Append trusted host fingerprint to known_hosts.
 * @internal
 */
static int noxssh_append_known_host(const char * known_hosts_path,
                                    const char * host,
                                    uint16_t port,
                                    const char * hex_fingerprint)
{
    FILE * f = NULL;

    if(known_hosts_path == NULL || host == NULL || hex_fingerprint == NULL) {
        return -1;
    }
    if(noxssh_ensure_known_hosts_dir(known_hosts_path) != 0) {
        return -1;
    }
    f = fopen(known_hosts_path, "a");
    if(f == NULL) {
        return -1;
    }
    (void)fprintf(f, "%s %u %s\n", host, (unsigned int)port, hex_fingerprint);
    (void)fclose(f);
    return 0;
}

/**
 * @brief Enforce host key trust policy using known_hosts fingerprint records.
 * @internal
 *
 * @return 1 when trusted, 0 when rejected.
 */
static int noxssh_verify_host_key(const char * host,
                                  uint16_t port,
                                  const uint8_t * fingerprint,
                                  uint32_t fingerprint_len,
                                  int strict_host_key_checking,
                                  const char * pinned_fingerprint_hex,
                                  int batch_mode,
                                  const char * known_hosts_override)
{
    char known_hosts_path[NOXSSH_MAX_PATH_LEN];
    char actual_hex[NOXSSH_HOSTKEY_HEX_LEN + 1u];
    char known_hex[NOXSSH_HOSTKEY_HEX_LEN + 1u];
    char answer[16];
    int lookup_rc = 0;

    if(host == NULL || fingerprint == NULL || fingerprint_len != NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN) {
        return 0;
    }
    noxssh_bytes_to_hex(fingerprint, fingerprint_len, actual_hex, (uint32_t)sizeof(actual_hex));
    printf("Server host key SHA256: %s\n", actual_hex);
    if(pinned_fingerprint_hex != NULL && pinned_fingerprint_hex[0] != '\0') {
        if(strcmp(actual_hex, pinned_fingerprint_hex) != 0) {
            printf("ERROR: Host key pin mismatch.\n");
            printf("Pinned:   %s\n", pinned_fingerprint_hex);
            printf("Observed: %s\n", actual_hex);
            return 0;
        }
        return 1;
    }

    if(known_hosts_override != NULL && known_hosts_override[0] != '\0') {
        strncpy(known_hosts_path, known_hosts_override, sizeof(known_hosts_path) - 1u);
        known_hosts_path[sizeof(known_hosts_path) - 1u] = '\0';
    } else {
        if(noxssh_get_known_hosts_path(known_hosts_path, (uint32_t)sizeof(known_hosts_path)) != 0) {
            printf("ERROR: Unable to resolve known_hosts path.\n");
            return 0;
        }
    }
    known_hex[0] = '\0';
    lookup_rc = noxssh_lookup_known_host(known_hosts_path,
                                         host,
                                         port,
                                         known_hex,
                                         (uint32_t)sizeof(known_hex));
    if(lookup_rc > 0) {
        if(strcmp(known_hex, actual_hex) == 0) {
            return 1;
        }
        printf("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n");
        printf("Expected: %s\n", known_hex);
        printf("Received: %s\n", actual_hex);
        if(strict_host_key_checking == NOXSSH_HOSTKEY_CHECK_NO) {
            printf("WARNING: StrictHostKeyChecking=no, continuing despite changed host key.\n");
            return 1;
        }
        printf("Host key verification failed.\n");
        return 0;
    }
    if(strict_host_key_checking == NOXSSH_HOSTKEY_CHECK_YES) {
        printf("ERROR: Unknown host key for %s:%u (strict checking enabled).\n",
               host,
               (unsigned int)port);
        return 0;
    }
    if(strict_host_key_checking == NOXSSH_HOSTKEY_CHECK_NO) {
        printf("WARNING: Unknown host key for %s:%u accepted (StrictHostKeyChecking=no).\n",
               host,
               (unsigned int)port);
        return 1;
    }
    if(strict_host_key_checking == NOXSSH_HOSTKEY_CHECK_ACCEPT_NEW) {
        if(noxssh_append_known_host(known_hosts_path, host, port, actual_hex) != 0) {
            printf("ERROR: Failed to persist accepted host key to %s\n", known_hosts_path);
            return 0;
        }
        printf("Host key accepted (accept-new) and saved to %s\n", known_hosts_path);
        return 1;
    }
    if(batch_mode != 0) {
        printf("ERROR: Unknown host key for %s:%u (batch mode disables ask prompt).\n",
               host,
               (unsigned int)port);
        return 0;
    }

    printf("The authenticity of host '%s:%u' can't be established.\n",
           host,
           (unsigned int)port);
    printf("Do you trust this host key? Type 'yes' to continue: ");
    fflush(stdout);
    if(fgets(answer, sizeof(answer), stdin) == NULL) {
        return 0;
    }
    if(strcmp(answer, "yes\n") != 0 && strcmp(answer, "yes\r\n") != 0) {
        printf("Host key not trusted. Aborting.\n");
        return 0;
    }
    if(noxssh_append_known_host(known_hosts_path, host, port, actual_hex) != 0) {
        printf("ERROR: Failed to persist trusted host key to %s\n", known_hosts_path);
        return 0;
    }
    printf("Host key trusted and saved to %s\n", known_hosts_path);
    return 1;
}

/**
 * @brief Print CLI usage text.
 *
 * @param prog Program name from argv[0].
 */
static void noxssh_print_usage(const char * prog)
{
    printf("%s " NOXSSH_VERSION_STRING "\n", (prog != NULL ? prog : "noxssh"));
    printf("Using NoxTLS Library %s\n", NOXTLS_VERSION_STRING);
    printf("Usage: %s [-h] [-d|-dd|-ddd] [-T] [--batch] [--strict-host-key] [--strict-host-key-checking mode] [--host-key-pin hex] [--known-hosts-file path] [--ed25519-key hex] [-i identity_file] [--connect-retries n] [--connect-timeout ms] [--io-timeout ms] [--server-alive-interval sec] [--server-alive-count-max n] [--rekey-interval sec] [-p port] [-w password] [user@]host [command]\n", (prog != NULL ? prog : "noxssh"));
    printf("Options:\n");
    printf("  -h, --help     Show this help and exit.\n");
    printf("  -d             Enable basic SSH debug output.\n");
    printf("  -dd            Enable verbose SSH debug output.\n");
    printf("  -ddd           Enable packet-level SSH debug output.\n");
    printf("  -T             Disable PTY allocation for shell sessions.\n");
    printf("  --batch            Disable interactive prompts (automation mode).\n");
    printf("  --strict-host-key  Reject unknown hosts (no TOFU prompt).\n");
    printf("  --strict-host-key-checking mode  Host key mode: yes|no|accept-new|ask.\n");
    printf("  --host-key-pin hex  Require exact SHA256 host key fingerprint (64 hex).\n");
    printf("  --known-hosts-file path  Override known_hosts file path.\n");
    printf("  --ed25519-key hex   Ed25519 private key seed for publickey auth (64 hex).\n");
    printf("  -i identity_file    Load Ed25519 key (hex seed or unencrypted OpenSSH key).\n");
    printf("  --connect-retries n Retry TCP connect n times (default: 0).\n");
    printf("  --connect-timeout ms  TCP connect timeout per attempt in milliseconds (default: 0).\n");
    printf("  --io-timeout ms     Socket I/O timeout for recv/send operations (default: 0).\n");
    printf("  --server-alive-interval sec  Send keepalive every sec of inactivity (default: 0=off).\n");
    printf("  --server-alive-count-max n  Disconnect after n unanswered keepalives (default: 3).\n");
    printf("  --rekey-interval sec      Trigger SSH rekey every sec (default: 0=off).\n");
    printf("  -p port        SSH server port (default: 22).\n");
    printf("  -w password   Password (avoid on command line in production).\n");
    printf("Examples:\n");
    printf("  %s user@example.com\n", prog);
    printf("  %s -p 2222 user@example.com\n", prog);
    printf("  %s -w secret user@example.com \"uname -a\"\n", prog);
    printf("  %s -d admin@192.168.2.71\n", prog);
    printf("  %s user@example.com \"uname -a\"\n", prog);
}

/**
 * @brief Send callback used by netnox_ssh transport layer.
 * @internal
 *
 * @param user_data noxssh_conn_t pointer.
 * @param data Buffer to send.
 * @param len Buffer length in bytes.
 *
 * @return Number of bytes sent, or -1 on error.
 */
static int32_t noxssh_send_cb(void * user_data, const uint8_t * data, uint32_t len)
{
    noxssh_conn_t * conn = (noxssh_conn_t *)user_data;

    if(conn == NULL || data == NULL) {
        return -1;
    }

#ifdef _WIN32
    return send(conn->sock, (const char *)data, (int)len, 0);
#else
    return (int32_t)send(conn->sock, data, (size_t)len, 0);
#endif
}

/**
 * @brief Receive callback used by netnox_ssh transport layer.
 * @internal
 *
 * @param user_data noxssh_conn_t pointer.
 * @param data Output buffer.
 * @param len Max bytes to read.
 *
 * @return Number of bytes read, or -1 on error.
 */
static int32_t noxssh_recv_cb(void * user_data, uint8_t * data, uint32_t len)
{
    noxssh_conn_t * conn = (noxssh_conn_t *)user_data;

    if(conn == NULL || data == NULL) {
        return -1;
    }

#ifdef _WIN32
    return recv(conn->sock, (char *)data, (int)len, 0);
#else
    return (int32_t)recv(conn->sock, data, (size_t)len, 0);
#endif
}

/**
 * @brief Poll socket readability with timeout.
 * @internal
 *
 * @param sock Connected socket.
 * @param timeout_ms Timeout in milliseconds.
 *
 * @return >0 when readable, 0 on timeout, <0 on error.
 */
static int noxssh_socket_readable(app_socket_t sock, uint32_t timeout_ms)
{
    fd_set read_fds;
    struct timeval tv;

    if(sock == APP_INVALID_SOCKET) {
        return -1;
    }

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    tv.tv_sec = (long)(timeout_ms / 1000u);
    tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);

#ifdef _WIN32
    return (int)select(0, &read_fds, NULL, NULL, &tv);
#else
    return (int)select(sock + 1, &read_fds, NULL, NULL, &tv);
#endif
}

static int noxssh_wait_socket_or_keepalive(netnox_ssh_client_t * client,
                                           noxssh_conn_t * conn,
                                           uint32_t wait_ms,
                                           uint32_t keepalive_interval_sec,
                                           uint32_t keepalive_count_max,
                                           uint32_t rekey_interval_sec,
                                           uint64_t * io_quiet_since_sec,
                                           uint32_t * unanswered_keepalive_count,
                                           uint64_t * last_rekey_sec)
{
    uint32_t remaining = wait_ms;
    uint32_t slice_ms = 250u;
    int ready = 0;
    uint64_t now_sec = 0u;

    if(client == NULL || conn == NULL) {
        return -1;
    }

    if(wait_ms == 0u) {
        return noxssh_socket_readable(conn->sock, 0u);
    }

    while(remaining > 0u) {
        if(noxssh_maybe_rekey(client, rekey_interval_sec, last_rekey_sec) < 0) {
            return -1;
        }
        uint32_t step = (remaining < slice_ms) ? remaining : slice_ms;
        ready = noxssh_socket_readable(conn->sock, step);
        if(ready != 0) {
            return ready;
        }
        remaining -= step;
        if(keepalive_interval_sec == 0u || io_quiet_since_sec == NULL || unanswered_keepalive_count == NULL) {
            continue;
        }
        now_sec = noxssh_now_seconds();
        if(now_sec >= (*io_quiet_since_sec + (uint64_t)keepalive_interval_sec)) {
            if(netnox_ssh_client_send_keepalive(client) != NETNOX_RETURN_SUCCESS) {
                return -1;
            }
            *unanswered_keepalive_count += 1u;
            if(keepalive_count_max > 0u && *unanswered_keepalive_count > keepalive_count_max) {
                return -2;
            }
            *io_quiet_since_sec = now_sec;
        }
    }
    return 0;
}

/**
 * @brief Parse [user@]host target into separate username and hostname buffers.
 * @internal
 *
 * @param target Input target argument.
 * @param username_out Output username buffer.
 * @param username_out_len Username buffer length.
 * @param host_out Output host buffer.
 * @param host_out_len Host buffer length.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_BAD_PARAM on invalid input.
 */
static netnox_return_t noxssh_parse_target(const char * target,
                                           char * username_out,
                                           uint16_t username_out_len,
                                           char * host_out,
                                           uint16_t host_out_len)
{
    const char * at = NULL;
    size_t user_len = 0u;
    size_t host_len = 0u;

    if(target == NULL || username_out == NULL || host_out == NULL || username_out_len == 0u || host_out_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    at = strchr(target, '@');
    if(at == NULL) {
        if(strlen(NOXSSH_DEFAULT_USER) >= (size_t)username_out_len) {
            return NETNOX_RETURN_BAD_PARAM;
        }
        strcpy(username_out, NOXSSH_DEFAULT_USER);

        host_len = strlen(target);
        if(host_len == 0u || host_len >= (size_t)host_out_len) {
            return NETNOX_RETURN_BAD_PARAM;
        }
        strcpy(host_out, target);
        return NETNOX_RETURN_SUCCESS;
    }

    user_len = (size_t)(at - target);
    host_len = strlen(at + 1);
    if(user_len == 0u || host_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(user_len >= (size_t)username_out_len || host_len >= (size_t)host_out_len) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    memcpy(username_out, target, user_len);
    username_out[user_len] = '\0';
    memcpy(host_out, at + 1, host_len);
    host_out[host_len] = '\0';
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Connect TCP socket to host:port.
 * @internal
 *
 * @param host Hostname or IP address.
 * @param port Destination TCP port.
 * @param out_sock Output socket handle.
 *
 * @return 0 on success, -1 on error.
 */
static int noxssh_connect_tcp(const char * host, uint16_t port, app_socket_t * out_sock, uint32_t timeout_ms)
{
    struct addrinfo hints;
    struct addrinfo * results = NULL;
    struct addrinfo * it = NULL;
    char port_str[8];
    app_socket_t sock = APP_INVALID_SOCKET;
    int gai_rc = 0;

    if(host == NULL || out_sock == NULL) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);
    gai_rc = getaddrinfo(host, port_str, &hints, &results);
    if(gai_rc != 0 || results == NULL) {
        return -1;
    }

    for(it = results; it != NULL; it = it->ai_next) {
        sock = (app_socket_t)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(sock == APP_INVALID_SOCKET) {
            continue;
        }
        if(noxssh_connect_with_timeout(sock, it->ai_addr, (int)it->ai_addrlen, timeout_ms) == 0) {
            *out_sock = sock;
            freeaddrinfo(results);
            return 0;
        }
        APP_CLOSESOCK(sock);
    }

    freeaddrinfo(results);
    return -1;
}

/**
 * @brief Prompt for password from stdin with input hidden (no echo).
 * @internal
 *
 * @param out_password Output password buffer.
 * @param out_password_len Output buffer length.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_BAD_PARAM on invalid input.
 */
static netnox_return_t noxssh_prompt_password(char * out_password, uint16_t out_password_len)
{
    uint16_t len = 0u;
    int c = 0;

    if(out_password == NULL || out_password_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    out_password[0] = '\0';

    printf("%s", "Password: ");
    fflush(stdout);

#ifdef _WIN32
    for(;;) {
        c = _getch();
        if(c == '\r' || c == '\n') {
            break;
        }
        if(c == '\b') {
            if(len > 0u) {
                len--;
                out_password[len] = '\0';
            }
            continue;
        }
        if(c == 0 || c == 0xE0) {
            (void)_getch();
            continue;
        }
        if(len < out_password_len - 1u) {
            out_password[len++] = (char)(unsigned char)c;
            out_password[len] = '\0';
        }
    }
#else
    {
        struct termios old_term;
        struct termios new_term;

        if(tcgetattr(STDIN_FILENO, &old_term) != 0) {
            if(fgets(out_password, out_password_len, stdin) == NULL) {
                return NETNOX_RETURN_BAD_PARAM;
            }
            len = (uint16_t)strlen(out_password);
            if(len > 0u && (out_password[len - 1u] == '\n' || out_password[len - 1u] == '\r')) {
                out_password[len - 1u] = '\0';
            }
            return NETNOX_RETURN_SUCCESS;
        }
        new_term = old_term;
        new_term.c_lflag &= (tcflag_t)~(ECHO);
        if(tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            if(fgets(out_password, out_password_len, stdin) == NULL) {
                return NETNOX_RETURN_BAD_PARAM;
            }
            len = (uint16_t)strlen(out_password);
            if(len > 0u && (out_password[len - 1u] == '\n' || out_password[len - 1u] == '\r')) {
                out_password[len - 1u] = '\0';
            }
            return NETNOX_RETURN_SUCCESS;
        }
        if(fgets(out_password, out_password_len, stdin) == NULL) {
            (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            return NETNOX_RETURN_BAD_PARAM;
        }
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        len = (uint16_t)strlen(out_password);
        if(len > 0u && (out_password[len - 1u] == '\n' || out_password[len - 1u] == '\r')) {
            out_password[len - 1u] = '\0';
        }
    }
#endif

    putchar('\n');
    fflush(stdout);
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Read and print channel output until channel closes.
 * @internal
 *
 * @param client Initialized SSH client context.
 */
static void noxssh_print_channel_output(netnox_ssh_client_t * client,
                                        noxssh_conn_t * conn,
                                        uint32_t keepalive_interval_sec,
                                        uint32_t keepalive_count_max,
                                        uint32_t rekey_interval_sec)
{
    uint8_t rx_buf[NETNOX_SSH_MAX_DATA_LEN];
    uint32_t rx_len = 0u;
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int ready = 0;
    uint64_t io_quiet_since_sec = 0u;
    uint32_t unanswered_keepalive_count = 0u;
    uint64_t last_rekey_sec = 0u;

    if(client == NULL || conn == NULL) {
        return;
    }
    io_quiet_since_sec = noxssh_now_seconds();
    last_rekey_sec = io_quiet_since_sec;

    for(;;) {
        ready = noxssh_wait_socket_or_keepalive(client,
                                                conn,
                                                1000u,
                                                keepalive_interval_sec,
                                                keepalive_count_max,
                                                rekey_interval_sec,
                                                &io_quiet_since_sec,
                                                &unanswered_keepalive_count,
                                                &last_rekey_sec);
        if(ready < 0) {
            if(ready == -2) {
                printf("ERROR: Server alive timeout reached (no response after %u keepalives).\n",
                       (unsigned)keepalive_count_max);
            } else {
                printf("ERROR: Connection lost while waiting for remote output.\n");
            }
            return;
        }
        if(ready == 0) {
            continue;
        }
        rx_len = (uint32_t)sizeof(rx_buf);
        rc = netnox_ssh_client_recv_data(client, rx_buf, &rx_len);
        if(rc != NETNOX_RETURN_SUCCESS) {
            return;
        }
        if(rx_len == 0u) {
            return;
        }
        fwrite(rx_buf, 1u, (size_t)rx_len, stdout);
        fflush(stdout);
        io_quiet_since_sec = noxssh_now_seconds();
        unanswered_keepalive_count = 0u;
    }
}

/**
 * @brief Drain available shell output packets and print to stdout.
 * @internal
 *
 * @param client Initialized SSH client context.
 * @param conn Active socket context.
 * @param first_wait_ms Time to wait for first packet before returning.
 *
 * @return 0 when no fatal error, 1 when channel closed, -1 on receive error.
 */
static int noxssh_drain_shell_output(netnox_ssh_client_t * client,
                                     noxssh_conn_t * conn,
                                     uint32_t first_wait_ms,
                                     uint32_t keepalive_interval_sec,
                                     uint32_t keepalive_count_max,
                                     uint32_t rekey_interval_sec,
                                     uint64_t * io_quiet_since_sec,
                                     uint32_t * unanswered_keepalive_count,
                                     uint64_t * last_rekey_sec)
{
    uint8_t rx_buf[NETNOX_SSH_MAX_DATA_LEN];
    uint32_t rx_len = 0u;
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int ready = 0;

    if(client == NULL || conn == NULL) {
        return -1;
    }

    ready = noxssh_wait_socket_or_keepalive(client,
                                            conn,
                                            first_wait_ms,
                                            keepalive_interval_sec,
                                            keepalive_count_max,
                                            rekey_interval_sec,
                                            io_quiet_since_sec,
                                            unanswered_keepalive_count,
                                            last_rekey_sec);
    if(ready == -2) {
        return -2;
    }
    if(ready <= 0) {
        return 0;
    }

    for(;;) {
        rx_len = (uint32_t)sizeof(rx_buf);
        rc = netnox_ssh_client_recv_data(client, rx_buf, &rx_len);
        if(rc != NETNOX_RETURN_SUCCESS) {
            return -1;
        }
        if(rx_len == 0u) {
            return 1;
        }
        fwrite(rx_buf, 1u, (size_t)rx_len, stdout);
        fflush(stdout);
        if(io_quiet_since_sec != NULL) {
            *io_quiet_since_sec = noxssh_now_seconds();
        }
        if(unanswered_keepalive_count != NULL) {
            *unanswered_keepalive_count = 0u;
        }

        ready = noxssh_wait_socket_or_keepalive(client,
                                                conn,
                                                60u,
                                                keepalive_interval_sec,
                                                keepalive_count_max,
                                                rekey_interval_sec,
                                                io_quiet_since_sec,
                                                unanswered_keepalive_count,
                                                last_rekey_sec);
        if(ready == -2) {
            return -2;
        }
        if(ready <= 0) {
            break;
        }
    }
    return 0;
}

/**
 * @brief Interactive shell loop: send user lines and print returned output.
 * @internal
 *
 * @param client Initialized SSH client context with open session shell.
 * @param conn Active socket context.
 */
static void noxssh_interactive_shell(netnox_ssh_client_t * client,
                                     noxssh_conn_t * conn,
                                     uint32_t keepalive_interval_sec,
                                     uint32_t keepalive_count_max,
                                     uint32_t rekey_interval_sec)
{
    char line[NETNOX_SSH_MAX_COMMAND_LEN + 2u];
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int drain_rc = 0;
    uint64_t io_quiet_since_sec = 0u;
    uint32_t unanswered_keepalive_count = 0u;
    uint64_t last_rekey_sec = 0u;

    if(client == NULL || conn == NULL) {
        return;
    }
    io_quiet_since_sec = noxssh_now_seconds();
    last_rekey_sec = io_quiet_since_sec;

    printf("Interactive shell mode. Type 'exit' to quit.\n");
    for(;;) {
        drain_rc = noxssh_drain_shell_output(client,
                                             conn,
                                             250u,
                                             keepalive_interval_sec,
                                             keepalive_count_max,
                                             rekey_interval_sec,
                                             &io_quiet_since_sec,
                                             &unanswered_keepalive_count,
                                             &last_rekey_sec);
        if(drain_rc < 0) {
            if(drain_rc == -2) {
                printf("ERROR: Server alive timeout reached (no response after %u keepalives).\n",
                       (unsigned)keepalive_count_max);
            } else {
                printf("ERROR: Failed to receive shell output.\n");
            }
            break;
        }
        if(drain_rc > 0) {
            printf("Remote channel closed.\n");
            break;
        }

        if(fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        if(strcmp(line, "exit\n") == 0 || strcmp(line, "exit\r\n") == 0) {
            break;
        }

        rc = netnox_ssh_client_send_data(client, (const uint8_t *)line, (uint32_t)strlen(line));
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to send input to remote shell.\n");
            break;
        }
        io_quiet_since_sec = noxssh_now_seconds();
        unanswered_keepalive_count = 0u;

        drain_rc = noxssh_drain_shell_output(client,
                                             conn,
                                             300u,
                                             keepalive_interval_sec,
                                             keepalive_count_max,
                                             rekey_interval_sec,
                                             &io_quiet_since_sec,
                                             &unanswered_keepalive_count,
                                             &last_rekey_sec);
        if(drain_rc < 0) {
            if(drain_rc == -2) {
                printf("ERROR: Server alive timeout reached (no response after %u keepalives).\n",
                       (unsigned)keepalive_count_max);
            } else {
                printf("ERROR: Failed to receive shell output.\n");
            }
            break;
        }
        if(drain_rc > 0) {
            printf("Remote channel closed.\n");
            break;
        }
    }
}

int main(int argc, char ** argv)
{
    uint16_t port = NETNOX_SSH_DEFAULT_PORT;
    const char * target = NULL;
    char username[NOXSSH_MAX_USER_LEN + 1u];
    char host[NOXSSH_MAX_HOST_LEN + 1u];
    char command[NOXSSH_MAX_COMMAND_LEN + 1u];
    char password[NOXSSH_MAX_PASSWORD_LEN + 1u];
    int password_set = 0;
    int command_set = 0;
    int request_pty = 1;
    int batch_mode = 0;
    int batch_mode_set_cli = 0;
    int strict_host_key_checking = NOXSSH_HOSTKEY_CHECK_ASK;
    int strict_host_key_checking_set_cli = 0;
    int connect_retries = 0;
    uint32_t connect_timeout_ms = 0u;
    int connect_timeout_set_cli = 0;
    uint32_t io_timeout_ms = 0u;
    uint32_t server_alive_interval_sec = 0u;
    int server_alive_interval_set_cli = 0;
    uint32_t server_alive_count_max = 3u;
    int server_alive_count_max_set_cli = 0;
    uint32_t rekey_interval_sec = 0u;
    int rekey_interval_set_cli = 0;
    int port_set_cli = 0;
    uint8_t ed25519_private_key[32];
    int ed25519_key_set = 0;
    char identity_file_path[NOXSSH_MAX_PATH_LEN];
    int identity_file_set = 0;
    char auto_identity_path[NOXSSH_MAX_PATH_LEN];
    char known_hosts_file_path[NOXSSH_MAX_PATH_LEN];
    int known_hosts_file_set_cli = 0;
    char pinned_hostkey_hex[NOXSSH_HOSTKEY_HEX_LEN + 1u];
    int debug_level = 0;
    int i = 0;
    noxssh_conn_t conn;
    noxssh_ssh_config_t ssh_cfg;
    netnox_ssh_client_t client;
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int app_exit_code = 0;

#ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("ERROR: WSAStartup failed\n");
        return 1;
    }
#endif

    memset(username, 0, sizeof(username));
    memset(host, 0, sizeof(host));
    memset(command, 0, sizeof(command));
    memset(password, 0, sizeof(password));
    memset(ed25519_private_key, 0, sizeof(ed25519_private_key));
    memset(identity_file_path, 0, sizeof(identity_file_path));
    memset(auto_identity_path, 0, sizeof(auto_identity_path));
    memset(known_hosts_file_path, 0, sizeof(known_hosts_file_path));
    memset(pinned_hostkey_hex, 0, sizeof(pinned_hostkey_hex));
    memset(&ssh_cfg, 0, sizeof(ssh_cfg));
    conn.sock = APP_INVALID_SOCKET;

    if(argc < 2) {
        noxssh_print_usage(argv[0]);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    for(i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-p") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_port = 0ul;
            if(i + 1 >= argc) {
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_port = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_port == 0ul || parsed_port > 65535ul) {
                printf("ERROR: Invalid port: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            port = (uint16_t)parsed_port;
            port_set_cli = 1;
            i++;
            continue;
        }

        if(strcmp(argv[i], "--connect-retries") == 0) {
            char * end_ptr = NULL;
            long parsed_retries = 0;
            if(i + 1 >= argc) {
                printf("ERROR: --connect-retries requires an integer value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_retries = strtol(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_retries < 0 || parsed_retries > 100) {
                printf("ERROR: Invalid --connect-retries value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            connect_retries = (int)parsed_retries;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--connect-timeout") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_timeout = 0ul;
            if(i + 1 >= argc) {
                printf("ERROR: --connect-timeout requires a millisecond value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_timeout = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_timeout > 600000ul) {
                printf("ERROR: Invalid --connect-timeout value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            connect_timeout_ms = (uint32_t)parsed_timeout;
            connect_timeout_set_cli = 1;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--io-timeout") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_timeout = 0ul;
            if(i + 1 >= argc) {
                printf("ERROR: --io-timeout requires a millisecond value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_timeout = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_timeout > 600000ul) {
                printf("ERROR: Invalid --io-timeout value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            io_timeout_ms = (uint32_t)parsed_timeout;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--server-alive-interval") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_interval = 0ul;
            if(i + 1 >= argc) {
                printf("ERROR: --server-alive-interval requires a second value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_interval = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_interval > 3600ul) {
                printf("ERROR: Invalid --server-alive-interval value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            server_alive_interval_sec = (uint32_t)parsed_interval;
            server_alive_interval_set_cli = 1;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--server-alive-count-max") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_count = 0ul;
            if(i + 1 >= argc) {
                printf("ERROR: --server-alive-count-max requires a count value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_count = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_count > 100ul) {
                printf("ERROR: Invalid --server-alive-count-max value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            server_alive_count_max = (uint32_t)parsed_count;
            server_alive_count_max_set_cli = 1;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--rekey-interval") == 0) {
            char * end_ptr = NULL;
            unsigned long parsed_interval = 0ul;
            if(i + 1 >= argc) {
                printf("ERROR: --rekey-interval requires a second value.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            parsed_interval = strtoul(argv[i + 1], &end_ptr, 10);
            if(end_ptr == argv[i + 1] || *end_ptr != '\0' || parsed_interval > 86400ul) {
                printf("ERROR: Invalid --rekey-interval value: %s\n", argv[i + 1]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            rekey_interval_sec = (uint32_t)parsed_interval;
            rekey_interval_set_cli = 1;
            i++;
            continue;
        }

        if(strcmp(argv[i], "-i") == 0) {
            if(i + 1 >= argc) {
                printf("ERROR: -i requires a path to an identity file.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            strncpy(identity_file_path, argv[i + 1], NOXSSH_MAX_PATH_LEN - 1u);
            identity_file_path[NOXSSH_MAX_PATH_LEN - 1u] = '\0';
            identity_file_set = 1;
            i++;
            continue;
        }

        if(strcmp(argv[i], "-w") == 0) {
            if(i + 1 >= argc) {
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            strncpy(password, argv[i + 1], NOXSSH_MAX_PASSWORD_LEN);
            password[NOXSSH_MAX_PASSWORD_LEN] = '\0';
            password_set = 1;
            i++;
            continue;
        }

        if(strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "-dd") == 0 || strcmp(argv[i], "-ddd") == 0) {
            debug_level = (int)strlen(argv[i]) - 1; /* "-d"=1, "-dd"=2, "-ddd"=3 */
            if(debug_level > 3) {
                debug_level = 3;
            }
            continue;
        }

        if(strcmp(argv[i], "-T") == 0) {
            request_pty = 0;
            continue;
        }
        if(strcmp(argv[i], "--batch") == 0) {
            batch_mode = 1;
            batch_mode_set_cli = 1;
            continue;
        }

        if(strcmp(argv[i], "--strict-host-key") == 0) {
            strict_host_key_checking = NOXSSH_HOSTKEY_CHECK_YES;
            strict_host_key_checking_set_cli = 1;
            continue;
        }
        if(strcmp(argv[i], "--strict-host-key-checking") == 0) {
            if(i + 1 >= argc) {
                printf("ERROR: --strict-host-key-checking requires a mode.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            if(noxssh_parse_strict_host_key_mode(argv[i + 1], &strict_host_key_checking) != 0) {
                printf("ERROR: Invalid --strict-host-key-checking value: %s\n", argv[i + 1]);
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            strict_host_key_checking_set_cli = 1;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--host-key-pin") == 0) {
            if(i + 1 >= argc) {
                printf("ERROR: --host-key-pin requires a 64-hex fingerprint argument.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            if(noxssh_is_valid_hex_fingerprint(argv[i + 1]) == 0) {
                printf("ERROR: Invalid --host-key-pin value. Expected %u hex chars.\n",
                       (unsigned)NOXSSH_HOSTKEY_HEX_LEN);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            strncpy(pinned_hostkey_hex, argv[i + 1], NOXSSH_HOSTKEY_HEX_LEN);
            pinned_hostkey_hex[NOXSSH_HOSTKEY_HEX_LEN] = '\0';
            noxssh_ascii_tolower_inplace(pinned_hostkey_hex);
            i++;
            continue;
        }
        if(strcmp(argv[i], "--known-hosts-file") == 0) {
            if(i + 1 >= argc) {
                printf("ERROR: --known-hosts-file requires a path.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            strncpy(known_hosts_file_path, argv[i + 1], NOXSSH_MAX_PATH_LEN - 1u);
            known_hosts_file_path[NOXSSH_MAX_PATH_LEN - 1u] = '\0';
            known_hosts_file_set_cli = 1;
            i++;
            continue;
        }
        if(strcmp(argv[i], "--ed25519-key") == 0) {
            if(i + 1 >= argc) {
                printf("ERROR: --ed25519-key requires a 64-hex private key seed.\n");
                noxssh_print_usage(argv[0]);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            if(strlen(argv[i + 1]) != NOXSSH_ED25519_KEY_HEX_LEN ||
               noxssh_hex_to_bytes(argv[i + 1],
                                   ed25519_private_key,
                                   (uint32_t)sizeof(ed25519_private_key)) != 0) {
                printf("ERROR: Invalid --ed25519-key value. Expected %u hex chars.\n",
                       (unsigned)NOXSSH_ED25519_KEY_HEX_LEN);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            ed25519_key_set = 1;
            i++;
            continue;
        }

        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            noxssh_print_usage(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        }

        if(argv[i][0] == '-') {
            printf("ERROR: Unknown option: %s\n", argv[i]);
            noxssh_print_usage(argv[0]);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        if(target == NULL) {
            target = argv[i];
            continue;
        }

        if(command_set == 0) {
            size_t cmd_len = 0u;
            command_set = 1;
            strncpy(command, argv[i], NOXSSH_MAX_COMMAND_LEN);
            command[NOXSSH_MAX_COMMAND_LEN] = '\0';
            cmd_len = strlen(command);
            if(cmd_len < NOXSSH_MAX_COMMAND_LEN) {
                uint16_t j = 0u;
                for(j = (uint16_t)(i + 1); j < (uint16_t)argc; j++) {
                    size_t remaining = NOXSSH_MAX_COMMAND_LEN - cmd_len;
                    size_t arg_len = strlen(argv[j]);
                    if(remaining < 2u || arg_len + 1u > remaining) {
                        break;
                    }
                    command[cmd_len++] = ' ';
                    memcpy(&command[cmd_len], argv[j], arg_len);
                    cmd_len += arg_len;
                    command[cmd_len] = '\0';
                    i = (int)j;
                }
            }
        }
    }

    if(target == NULL) {
        noxssh_print_usage(argv[0]);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    {
        char target_user[NOXSSH_MAX_USER_LEN + 1u];
        char target_host_alias[NOXSSH_MAX_HOST_LEN + 1u];
        const char * at = strchr(target, '@');
        size_t user_len = 0u;
        size_t host_len = 0u;
        target_user[0] = '\0';
        target_host_alias[0] = '\0';

        if(at != NULL) {
            user_len = (size_t)(at - target);
            host_len = strlen(at + 1);
            if(user_len == 0u || user_len > NOXSSH_MAX_USER_LEN || host_len == 0u || host_len > NOXSSH_MAX_HOST_LEN) {
                printf("ERROR: Invalid target: %s\n", target);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            memcpy(target_user, target, user_len);
            target_user[user_len] = '\0';
            memcpy(target_host_alias, at + 1, host_len);
            target_host_alias[host_len] = '\0';
        } else {
            host_len = strlen(target);
            if(host_len == 0u || host_len > NOXSSH_MAX_HOST_LEN) {
                printf("ERROR: Invalid target: %s\n", target);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            memcpy(target_host_alias, target, host_len);
            target_host_alias[host_len] = '\0';
        }

        (void)noxssh_load_ssh_config_for_host(target_host_alias, &ssh_cfg);
        if(port_set_cli == 0 && ssh_cfg.has_port != 0) {
            port = ssh_cfg.port;
        }
        if(strict_host_key_checking_set_cli == 0 && ssh_cfg.has_strict_host_key_checking != 0) {
            strict_host_key_checking = ssh_cfg.strict_host_key_checking;
        }
        if(batch_mode_set_cli == 0 && ssh_cfg.has_batch_mode != 0) {
            batch_mode = ssh_cfg.batch_mode;
        }
        if(connect_timeout_set_cli == 0 && ssh_cfg.has_connect_timeout_ms != 0) {
            connect_timeout_ms = ssh_cfg.connect_timeout_ms;
        }
        if(server_alive_interval_set_cli == 0 && ssh_cfg.has_server_alive_interval_sec != 0) {
            server_alive_interval_sec = ssh_cfg.server_alive_interval_sec;
        }
        if(server_alive_count_max_set_cli == 0 && ssh_cfg.has_server_alive_count_max != 0) {
            server_alive_count_max = ssh_cfg.server_alive_count_max;
        }
        if(rekey_interval_set_cli == 0 && ssh_cfg.has_rekey_interval_sec != 0) {
            rekey_interval_sec = ssh_cfg.rekey_interval_sec;
        }
        if(identity_file_set == 0 && ed25519_key_set == 0 && ssh_cfg.has_identity_file != 0) {
            strncpy(identity_file_path, ssh_cfg.identity_file, NOXSSH_MAX_PATH_LEN - 1u);
            identity_file_path[NOXSSH_MAX_PATH_LEN - 1u] = '\0';
            identity_file_set = 1;
        }
        if(known_hosts_file_set_cli == 0 && ssh_cfg.has_user_known_hosts_file != 0) {
            strncpy(known_hosts_file_path, ssh_cfg.user_known_hosts_file, NOXSSH_MAX_PATH_LEN - 1u);
            known_hosts_file_path[NOXSSH_MAX_PATH_LEN - 1u] = '\0';
        }

        if(target_user[0] != '\0') {
            strncpy(username, target_user, NOXSSH_MAX_USER_LEN);
            username[NOXSSH_MAX_USER_LEN] = '\0';
        } else if(ssh_cfg.has_user != 0) {
            strncpy(username, ssh_cfg.user, NOXSSH_MAX_USER_LEN);
            username[NOXSSH_MAX_USER_LEN] = '\0';
        } else {
            strncpy(username, NOXSSH_DEFAULT_USER, NOXSSH_MAX_USER_LEN);
            username[NOXSSH_MAX_USER_LEN] = '\0';
        }
        if(ssh_cfg.has_host_name != 0) {
            strncpy(host, ssh_cfg.host_name, NOXSSH_MAX_HOST_LEN);
            host[NOXSSH_MAX_HOST_LEN] = '\0';
        } else {
            strncpy(host, target_host_alias, NOXSSH_MAX_HOST_LEN);
            host[NOXSSH_MAX_HOST_LEN] = '\0';
        }
    }

    {
        int attempt = 0;
        int connected = 0;
        for(attempt = 0; attempt <= connect_retries; attempt++) {
            if(noxssh_connect_tcp(host, port, &conn.sock, connect_timeout_ms) == 0) {
                connected = 1;
                break;
            }
            if(attempt < connect_retries) {
                noxssh_sleep_ms(1000u);
            }
        }
        if(!connected) {
        printf("ERROR: Failed TCP connect to %s:%u\n", host, (unsigned int)port);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
        }
    }
    if(io_timeout_ms > 0u) {
        if(noxssh_set_socket_io_timeout(conn.sock, io_timeout_ms) != 0) {
            printf("ERROR: Failed to configure socket I/O timeout (%u ms).\n", (unsigned)io_timeout_ms);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }

    if(debug_level != 0) {
        char debug_env[2];
        debug_env[0] = (char)('0' + debug_level);
        debug_env[1] = '\0';
#ifdef _WIN32
        _putenv_s("NETNOX_SSH_DEBUG", debug_env);
#else
        (void)setenv("NETNOX_SSH_DEBUG", debug_env, 1);
#endif
    } else {
#ifdef _WIN32
        _putenv_s("NETNOX_SSH_DEBUG", "");
#else
        (void)unsetenv("NETNOX_SSH_DEBUG");
#endif
    }

    rc = netnox_ssh_client_init(&client, NULL, port);
    if(rc != NETNOX_RETURN_SUCCESS) {
        printf("ERROR: netnox_ssh_client_init failed\n");
        APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    rc = netnox_ssh_client_set_target(&client, username, host);
    if(rc != NETNOX_RETURN_SUCCESS) {
        printf("ERROR: netnox_ssh_client_set_target failed\n");
        APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    netnox_ssh_client_set_io_callbacks(&client, noxssh_send_cb, noxssh_recv_cb, &conn);
    rc = netnox_ssh_client_connect(&client);
    if(rc != NETNOX_RETURN_SUCCESS) {
        printf("ERROR: SSH handshake failed (run with -d for details)\n");
        APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("Connected to %s:%u\n", host, (unsigned int)port);
    printf("Server identification: %s\n",
           (netnox_ssh_client_get_server_ident(&client) != NULL) ? netnox_ssh_client_get_server_ident(&client) : "<none>");
    {
        uint8_t hostkey_fp[NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN];
        uint32_t hostkey_fp_len = (uint32_t)sizeof(hostkey_fp);
        rc = netnox_ssh_client_get_server_host_key_fingerprint(&client, hostkey_fp, &hostkey_fp_len);
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to retrieve server host key fingerprint.\n");
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        if(noxssh_verify_host_key(host,
                                  port,
                                  hostkey_fp,
                                  hostkey_fp_len,
                                  strict_host_key_checking,
                                  pinned_hostkey_hex,
                                  batch_mode,
                                  known_hosts_file_path) == 0) {
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }

    if(ed25519_key_set != 0) {
        rc = netnox_ssh_client_set_ed25519_private_key(&client, ed25519_private_key);
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to configure Ed25519 private key.\n");
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }
    if(identity_file_set != 0) {
        int key_load_rc = noxssh_load_ed25519_seed_file(identity_file_path, ed25519_private_key);
        if(key_load_rc != NOXSSH_KEY_LOAD_SUCCESS) {
            if(key_load_rc == NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED) {
                printf("ERROR: Encrypted OpenSSH private keys are not supported yet: %s\n", identity_file_path);
            } else {
                printf("ERROR: Failed to load Ed25519 key from file: %s\n", identity_file_path);
            }
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        rc = netnox_ssh_client_set_ed25519_private_key(&client, ed25519_private_key);
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Invalid Ed25519 private key seed in file: %s\n", identity_file_path);
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        ed25519_key_set = 1;
    }
    if(ed25519_key_set == 0) {
        int auto_rc = noxssh_try_load_default_identity(ed25519_private_key,
                                                       auto_identity_path,
                                                       (uint32_t)sizeof(auto_identity_path));
        if(auto_rc == NOXSSH_KEY_LOAD_SUCCESS) {
            rc = netnox_ssh_client_set_ed25519_private_key(&client, ed25519_private_key);
            if(rc == NETNOX_RETURN_SUCCESS) {
                ed25519_key_set = 1;
                printf("Loaded default identity: %s\n", auto_identity_path);
            }
        } else if(auto_rc == NOXSSH_KEY_LOAD_ENCRYPTED_UNSUPPORTED) {
            printf("Default identity is encrypted and unsupported right now: %s\n", auto_identity_path);
        }
    }

    if(password_set == 0 && ed25519_key_set == 0 && batch_mode == 0) {
        if(noxssh_prompt_password(password, (uint16_t)sizeof(password)) != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to read password from stdin.\n");
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        password_set = 1;
    }

    if(password_set != 0) {
        rc = netnox_ssh_client_set_password(&client, password);
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to configure password\n");
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

    }

    if(password_set != 0 || ed25519_key_set != 0) {
        rc = netnox_ssh_client_authenticate(&client);
        if(rc == NETNOX_RETURN_AUTH_REJECTED && password_set == 0 && ed25519_key_set != 0 && batch_mode == 0) {
            if(noxssh_prompt_password(password, (uint16_t)sizeof(password)) == NETNOX_RETURN_SUCCESS) {
                password_set = 1;
                if(netnox_ssh_client_set_password(&client, password) == NETNOX_RETURN_SUCCESS) {
                    rc = netnox_ssh_client_authenticate(&client);
                }
            }
        }
        if(rc != NETNOX_RETURN_SUCCESS) {
            if(rc == NETNOX_RETURN_AUTH_REJECTED) {
                printf("Server rejected authentication (credentials/key/user mismatch).\n");
            } else {
                printf("Authentication failed. Use -d for debug details.\n");
            }
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        printf("Authentication succeeded.\n");

        rc = netnox_ssh_client_open_session(&client);
        if(rc != NETNOX_RETURN_SUCCESS) {
            printf("ERROR: Failed to open SSH session channel.\n");
            (void)netnox_ssh_client_close(&client);
            APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }

        if(command_set != 0) {
            rc = netnox_ssh_client_exec(&client, command);
            if(rc != NETNOX_RETURN_SUCCESS) {
                printf("ERROR: Failed to execute remote command.\n");
                (void)netnox_ssh_client_close(&client);
                APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            noxssh_print_channel_output(&client,
                                        &conn,
                                        server_alive_interval_sec,
                                        server_alive_count_max,
                                        rekey_interval_sec);
            {
                uint32_t remote_status = 0u;
                if(netnox_ssh_client_get_remote_exit_status(&client, &remote_status) == NETNOX_RETURN_SUCCESS) {
                    app_exit_code = (int)(remote_status & 0xFFu);
                } else {
                    app_exit_code = 0;
                }
            }
        } else {
            rc = netnox_ssh_client_request_shell_ex(&client, (uint8_t)request_pty);
            if(rc != NETNOX_RETURN_SUCCESS) {
                printf("ERROR: Failed to request remote shell.\n");
                (void)netnox_ssh_client_close(&client);
                APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            noxssh_interactive_shell(&client,
                                     &conn,
                                     server_alive_interval_sec,
                                     server_alive_count_max,
                                     rekey_interval_sec);
        }
    }

    (void)netnox_ssh_client_close(&client);
    APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return app_exit_code;
}
