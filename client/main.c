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

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
typedef SOCKET app_socket_t;
#define APP_INVALID_SOCKET INVALID_SOCKET
#define APP_CLOSESOCK closesocket
#else
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
typedef int app_socket_t;
#define APP_INVALID_SOCKET (-1)
#define APP_CLOSESOCK close
#endif

#include "version.h"
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

/** Application socket context passed to netnox_ssh transport callbacks. */
typedef struct
{
    app_socket_t sock;
} noxssh_conn_t;

/**
 * @brief Print CLI usage text.
 *
 * @param prog Program name from argv[0].
 */
static void noxssh_print_usage(const char * prog)
{
    printf("%s " NOXSSH_VERSION_STRING "\n", (prog != NULL ? prog : "noxssh"));
    printf("Usage: %s [-h] [-d|-dd|-ddd] [-p port] [-w password] [user@]host [command]\n", (prog != NULL ? prog : "noxssh"));
    printf("Options:\n");
    printf("  -h, --help     Show this help and exit.\n");
    printf("  -d             Enable basic SSH debug output.\n");
    printf("  -dd            Enable verbose SSH debug output.\n");
    printf("  -ddd           Enable packet-level SSH debug output.\n");
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
static int noxssh_connect_tcp(const char * host, uint16_t port, app_socket_t * out_sock)
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
        if(connect(sock, it->ai_addr, (int)it->ai_addrlen) == 0) {
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
static void noxssh_print_channel_output(netnox_ssh_client_t * client)
{
    uint8_t rx_buf[NETNOX_SSH_MAX_DATA_LEN];
    uint32_t rx_len = 0u;
    netnox_return_t rc = NETNOX_RETURN_FAILED;

    if(client == NULL) {
        return;
    }

    for(;;) {
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
                                     uint32_t first_wait_ms)
{
    uint8_t rx_buf[NETNOX_SSH_MAX_DATA_LEN];
    uint32_t rx_len = 0u;
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int ready = 0;

    if(client == NULL || conn == NULL) {
        return -1;
    }

    ready = noxssh_socket_readable(conn->sock, first_wait_ms);
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

        ready = noxssh_socket_readable(conn->sock, 60u);
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
static void noxssh_interactive_shell(netnox_ssh_client_t * client, noxssh_conn_t * conn)
{
    char line[NETNOX_SSH_MAX_COMMAND_LEN + 2u];
    netnox_return_t rc = NETNOX_RETURN_FAILED;
    int drain_rc = 0;

    if(client == NULL || conn == NULL) {
        return;
    }

    printf("Interactive shell mode. Type 'exit' to quit.\n");
    for(;;) {
        drain_rc = noxssh_drain_shell_output(client, conn, 250u);
        if(drain_rc < 0) {
            printf("ERROR: Failed to receive shell output.\n");
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

        drain_rc = noxssh_drain_shell_output(client, conn, 300u);
        if(drain_rc < 0) {
            printf("ERROR: Failed to receive shell output.\n");
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
    int debug_level = 0;
    int i = 0;
    noxssh_conn_t conn;
    netnox_ssh_client_t client;
    netnox_return_t rc = NETNOX_RETURN_FAILED;

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

    rc = noxssh_parse_target(target, username, (uint16_t)sizeof(username), host, (uint16_t)sizeof(host));
    if(rc != NETNOX_RETURN_SUCCESS) {
        printf("ERROR: Invalid target: %s\n", target);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if(noxssh_connect_tcp(host, port, &conn.sock) != 0) {
        printf("ERROR: Failed TCP connect to %s:%u\n", host, (unsigned int)port);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
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

    if(password_set == 0) {
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

        rc = netnox_ssh_client_authenticate(&client);
        if(rc != NETNOX_RETURN_SUCCESS) {
            if(rc == NETNOX_RETURN_AUTH_REJECTED) {
                printf("Server rejected authentication (wrong password or user?).\n");
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
            noxssh_print_channel_output(&client);
        } else {
            rc = netnox_ssh_client_request_shell(&client);
            if(rc != NETNOX_RETURN_SUCCESS) {
                printf("ERROR: Failed to request remote shell.\n");
                (void)netnox_ssh_client_close(&client);
                APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
                WSACleanup();
#endif
                return 1;
            }
            noxssh_interactive_shell(&client, &conn);
        }
    }

    (void)netnox_ssh_client_close(&client);
    APP_CLOSESOCK(conn.sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
