/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon_runtime.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET noxsshd_sock_t;
#define NOXSSH_INVALID_SOCKET INVALID_SOCKET
#define NOXSSH_CLOSESOCK closesocket
#define NOXSSH_SOCKERR SOCKET_ERROR
#else
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
typedef int noxsshd_sock_t;
#define NOXSSH_INVALID_SOCKET (-1)
#define NOXSSH_CLOSESOCK close
#define NOXSSH_SOCKERR (-1)
#endif

typedef struct
{
    noxsshd_sock_t sock;
} noxsshd_conn_t;

static int32_t noxsshd_send_cb(void * user_data, const uint8_t * data, uint32_t len)
{
    noxsshd_conn_t * c = (noxsshd_conn_t *)user_data;
    if(c == NULL || data == NULL) {
        return -1;
    }
#ifdef _WIN32
    return send(c->sock, (const char *)data, (int)len, 0);
#else
    return (int32_t)send(c->sock, data, (size_t)len, 0);
#endif
}

static int32_t noxsshd_recv_cb(void * user_data, uint8_t * data, uint32_t len)
{
    noxsshd_conn_t * c = (noxsshd_conn_t *)user_data;
    if(c == NULL || data == NULL) {
        return -1;
    }
#ifdef _WIN32
    return recv(c->sock, (char *)data, (int)len, 0);
#else
    return (int32_t)recv(c->sock, data, (size_t)len, 0);
#endif
}

static int noxsshd_serve_connection(noxsshd_sock_t client_sock,
                                    const char * password,
                                    const uint8_t host_ed25519_seed[32])
{
    netnox_ssh_server_t srv;
    noxsshd_conn_t conn;
    netnox_return_t rc;

    conn.sock = client_sock;
    if(netnox_ssh_server_init(&srv) != NETNOX_RETURN_SUCCESS) {
        return 1;
    }
    netnox_ssh_server_set_io_callbacks(&srv, noxsshd_send_cb, noxsshd_recv_cb, &conn);
    if(netnox_ssh_server_set_host_ed25519_seed(&srv, host_ed25519_seed) != NETNOX_RETURN_SUCCESS) {
        return 1;
    }
    if(password != NULL && password[0] != '\0') {
        if(netnox_ssh_server_set_allowed_password(&srv, password) != NETNOX_RETURN_SUCCESS) {
            return 1;
        }
    }
    rc = netnox_ssh_server_serve_one(&srv);
    netnox_ssh_server_reset(&srv);
    return (rc == NETNOX_RETURN_SUCCESS) ? 0 : 1;
}

#ifndef _WIN32
static int noxsshd_listen_posix(const char * bind_host, uint16_t port,
                                  const char * password,
                                  const uint8_t host_ed25519_seed[32])
{
    struct addrinfo hints;
    struct addrinfo * res = NULL;
    struct addrinfo * rp = NULL;
    char portbuf[16];
    noxsshd_sock_t listen_fd = NOXSSH_INVALID_SOCKET;
    int yes = 1;
    int gai_err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    (void)snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    gai_err = getaddrinfo((bind_host != NULL && bind_host[0] != '\0') ? bind_host : NULL, portbuf, &hints, &res);
    if(gai_err != 0 || res == NULL) {
        fprintf(stderr, "noxsshd: getaddrinfo: %s\n", gai_strerror(gai_err));
        return 1;
    }
    for(rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = (noxsshd_sock_t)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(listen_fd == NOXSSH_INVALID_SOCKET) {
            continue;
        }
        if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, (socklen_t)sizeof(yes)) == NOXSSH_SOCKERR) {
            NOXSSH_CLOSESOCK(listen_fd);
            listen_fd = NOXSSH_INVALID_SOCKET;
            continue;
        }
        if(bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        NOXSSH_CLOSESOCK(listen_fd);
        listen_fd = NOXSSH_INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if(listen_fd == NOXSSH_INVALID_SOCKET) {
        fprintf(stderr, "noxsshd: bind failed\n");
        return 1;
    }
    if(listen(listen_fd, 8) != 0) {
        perror("noxsshd: listen");
        NOXSSH_CLOSESOCK(listen_fd);
        return 1;
    }
    fprintf(stderr, "noxsshd: listening (sequential accept)\n");
    for(;;) {
        noxsshd_sock_t client = accept(listen_fd, NULL, NULL);
        if(client == NOXSSH_INVALID_SOCKET) {
            perror("noxsshd: accept");
            continue;
        }
        (void)noxsshd_serve_connection(client, password, host_ed25519_seed);
        NOXSSH_CLOSESOCK(client);
    }
}
#else
static int noxsshd_listen_win32(const char * bind_host, uint16_t port,
                                const char * password,
                                const uint8_t host_ed25519_seed[32])
{
    struct addrinfo hints;
    struct addrinfo * res = NULL;
    struct addrinfo * rp = NULL;
    char portbuf[16];
    noxsshd_sock_t listen_fd = NOXSSH_INVALID_SOCKET;
    WSADATA wsa;
    int gai_err;

    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "noxsshd: WSAStartup failed\n");
        return 1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    (void)snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    gai_err = getaddrinfo((bind_host != NULL && bind_host[0] != '\0') ? bind_host : NULL, portbuf, &hints, &res);
    if(gai_err != 0 || res == NULL) {
        fprintf(stderr, "noxsshd: getaddrinfo failed %d\n", gai_err);
        WSACleanup();
        return 1;
    }
    for(rp = res; rp != NULL; rp = rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(listen_fd == INVALID_SOCKET) {
            continue;
        }
        {
            int yes = 1;
            if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) == SOCKET_ERROR) {
                closesocket(listen_fd);
                listen_fd = INVALID_SOCKET;
                continue;
            }
        }
        if(bind(listen_fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            break;
        }
        closesocket(listen_fd);
        listen_fd = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if(listen_fd == INVALID_SOCKET) {
        fprintf(stderr, "noxsshd: bind failed\n");
        WSACleanup();
        return 1;
    }
    if(listen(listen_fd, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "noxsshd: listen failed\n");
        closesocket(listen_fd);
        WSACleanup();
        return 1;
    }
    fprintf(stderr, "noxsshd: listening (sequential accept)\n");
    for(;;) {
        noxsshd_sock_t client = accept(listen_fd, NULL, NULL);
        if(client == INVALID_SOCKET) {
            fprintf(stderr, "noxsshd: accept failed\n");
            continue;
        }
        (void)noxsshd_serve_connection(client, password, host_ed25519_seed);
        closesocket(client);
    }
}
#endif

int noxsshd_listen_loop(const char * bind_host,
                        uint16_t port,
                        const char * password,
                        const uint8_t host_ed25519_seed[32])
{
#ifndef _WIN32
    return noxsshd_listen_posix(bind_host, port, password, host_ed25519_seed);
#else
    return noxsshd_listen_win32(bind_host, port, password, host_ed25519_seed);
#endif
}
