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
* File:    noxssh_common.h
* Summary: NoxSSH common SSH protocol API
*
*/

/**
 * @file noxssh_common.h
 * @brief NoxSSH common client protocol API.
 */

#ifndef _NOXSSH_COMMON_H_
#define _NOXSSH_COMMON_H_

#include <stdint.h>
#include "noxssh_common_config.h"

/**
 * Minimal return codes used by noxssh/netnox_ssh without full NetNox dependency.
 */
typedef enum
{
    NETNOX_RETURN_SUCCESS = 0,
    NETNOX_RETURN_FAILED,
    NETNOX_RETURN_BAD_PARAM,
    NETNOX_RETURN_NULL,
    NETNOX_RETURN_INSUFF_MEMORY,
    NETNOX_RETURN_PORT_IN_USE,
    NETNOX_RETURN_PORT_NOT_EXIT,
    NETNOX_RETURN_INVALID_PKT,
    NETNOX_RETURN_UNKNOWN_PROTOCOL,
    NETNOX_RETURN_AUTH_REJECTED
} netnox_return_t;

/** Opaque NetNox interface placeholder (unused by noxssh host-socket mode). */
typedef struct netnox_interface_s netnox_interface_t;

/** @brief Default SSH port (22). */
#define NETNOX_SSH_DEFAULT_PORT (22u)
/** @brief Default SSH client identification string. */
#define NETNOX_SSH_DEFAULT_CLIENT_IDENT "SSH-2.0-noxssh_0.1"

/** @brief SSH message number for service request. */
#define NETNOX_SSH_MSG_SERVICE_REQUEST (5u)
/** @brief SSH message number for ignore/no-op packets. */
#define NETNOX_SSH_MSG_IGNORE (2u)
/** @brief SSH message number for service accept. */
#define NETNOX_SSH_MSG_SERVICE_ACCEPT (6u)
/** @brief SSH message number for key exchange initialization. */
#define NETNOX_SSH_MSG_KEXINIT (20u)
/** @brief SSH message number for NEWKEYS. */
#define NETNOX_SSH_MSG_NEWKEYS (21u)
/** @brief SSH message number for ECDH key exchange init. */
#define NETNOX_SSH_MSG_KEX_ECDH_INIT (30u)
/** @brief SSH message number for ECDH key exchange reply. */
#define NETNOX_SSH_MSG_KEX_ECDH_REPLY (31u)
/** @brief SSH message number for userauth request. */
#define NETNOX_SSH_MSG_USERAUTH_REQUEST (50u)
/** @brief SSH message number for userauth failure. */
#define NETNOX_SSH_MSG_USERAUTH_FAILURE (51u)
/** @brief SSH message number for userauth success. */
#define NETNOX_SSH_MSG_USERAUTH_SUCCESS (52u)
/** @brief SSH message number for channel open. */
#define NETNOX_SSH_MSG_CHANNEL_OPEN (90u)
/** @brief SSH message number for channel open confirmation. */
#define NETNOX_SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91u)
/** @brief SSH message number for channel open failure. */
#define NETNOX_SSH_MSG_CHANNEL_OPEN_FAILURE (92u)
/** @brief SSH message number for channel data. */
#define NETNOX_SSH_MSG_CHANNEL_DATA (94u)
/** @brief SSH message number for channel extended data (stderr). */
#define NETNOX_SSH_MSG_CHANNEL_EXTENDED_DATA (95u)
/** @brief SSH message number for channel EOF. */
#define NETNOX_SSH_MSG_CHANNEL_EOF (96u)
/** @brief SSH message number for channel close. */
#define NETNOX_SSH_MSG_CHANNEL_CLOSE (97u)
/** @brief SSH message number for channel request. */
#define NETNOX_SSH_MSG_CHANNEL_REQUEST (98u)
/** @brief SSH message number for channel request success. */
#define NETNOX_SSH_MSG_CHANNEL_SUCCESS (99u)
/** @brief SSH message number for channel request failure. */
#define NETNOX_SSH_MSG_CHANNEL_FAILURE (100u)

/** @brief SSH service name for user authentication (RFC 4254). */
#define NETNOX_SSH_SERVICE_USERAUTH "ssh-userauth"
/** @brief SSH service name for connection (used in userauth request). */
#define NETNOX_SSH_SERVICE_CONNECTION "ssh-connection"
/** @brief Userauth method name for password (RFC 4252). */
#define NETNOX_SSH_AUTH_METHOD_PASSWORD "password"
/** @brief Userauth method name for public key (RFC 4252). */
#define NETNOX_SSH_AUTH_METHOD_PUBLICKEY "publickey"
/** @brief Public key algorithm name for Ed25519. */
#define NETNOX_SSH_KEYALG_ED25519 "ssh-ed25519"
/** @brief Channel type for session channels (RFC 4254). */
#define NETNOX_SSH_CHANNEL_TYPE_SESSION "session"
/** @brief Channel request type for exec. */
#define NETNOX_SSH_CHANNEL_REQ_EXEC "exec"
/** @brief Channel request type for shell. */
#define NETNOX_SSH_CHANNEL_REQ_SHELL "shell"
/** @brief SHA-256 fingerprint size in bytes. */
#define NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN (32u)

/** Callback to send data over the transport (socket/stream). Returns bytes sent or negative on error. */
typedef int32_t (*netnox_ssh_transport_send_t)(void * user_data, const uint8_t * data, uint32_t len);
/** Callback to receive data from the transport. Returns bytes received or negative on error. */
typedef int32_t (*netnox_ssh_transport_recv_t)(void * user_data, uint8_t * data, uint32_t len);

/** SSH client context (transport callbacks, identification strings, and protocol state). */
typedef struct
{
    netnox_interface_t * itf;
    netnox_ssh_transport_send_t send_cb;
    netnox_ssh_transport_recv_t recv_cb;
    void * io_user_data;

    char client_ident[NETNOX_SSH_MAX_IDENT_LEN + 1u];
    char server_ident[NETNOX_SSH_MAX_IDENT_LEN + 1u];
    char username[NETNOX_SSH_MAX_USERNAME_LEN + 1u];
    char host[NETNOX_SSH_MAX_HOST_LEN + 1u];
    char password[NETNOX_SSH_MAX_PASSWORD_LEN + 1u];
    uint8_t ed25519_private_key[32];
    uint8_t ed25519_public_key[32];
    uint8_t has_ed25519_key;

    uint16_t port;
    uint8_t connected;
    uint8_t kexinit_exchanged;
    uint8_t userauth_service_ready;
    uint8_t authenticated;
    uint8_t channel_open;
    uint8_t key_exchange_complete;
    uint32_t local_channel_id;
    uint32_t remote_channel_id;
    uint32_t local_window_size;
    uint32_t remote_window_size;
    uint32_t remote_max_packet_size;
    uint8_t kexinit_client_payload[NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN];
    uint8_t kexinit_server_payload[NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN];
    uint32_t kexinit_client_payload_len;
    uint32_t kexinit_server_payload_len;
    uint8_t server_host_key_blob[NETNOX_SSH_MAX_HOST_KEY_BLOB_LEN];
    uint32_t server_host_key_blob_len;
    uint8_t server_host_key_fingerprint[NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN];
    uint8_t server_host_key_ready;
    uint8_t session_id[32];
    uint8_t session_id_len;
    uint8_t shared_secret_raw[32];
    uint8_t c2s_iv[16];
    uint8_t s2c_iv[16];
    uint8_t c2s_key[16];
    uint8_t s2c_key[16];
    uint8_t c2s_mac_key[32];
    uint8_t s2c_mac_key[32];
    uint32_t send_seq;
    uint32_t recv_seq;
    uint8_t c2s_counter[16];
    uint8_t s2c_counter[16];
    uint8_t pending_newkeys[32];
    uint32_t pending_newkeys_len;
    uint8_t remote_exit_status_valid;
    uint32_t remote_exit_status;
} netnox_ssh_client_t;

extern netnox_return_t netnox_ssh_client_init(netnox_ssh_client_t * client,
                                              netnox_interface_t * itf,
                                              uint16_t port);
extern void netnox_ssh_client_set_io_callbacks(netnox_ssh_client_t * client,
                                               netnox_ssh_transport_send_t send_cb,
                                               netnox_ssh_transport_recv_t recv_cb,
                                               void * io_user_data);
extern netnox_return_t netnox_ssh_client_set_identification(netnox_ssh_client_t * client,
                                                            const char * client_ident);
extern netnox_return_t netnox_ssh_client_set_target(netnox_ssh_client_t * client,
                                                    const char * username,
                                                    const char * host);
extern netnox_return_t netnox_ssh_client_set_password(netnox_ssh_client_t * client,
                                                      const char * password);
extern netnox_return_t netnox_ssh_client_set_ed25519_private_key(netnox_ssh_client_t * client,
                                                                 const uint8_t private_key[32]);
extern netnox_return_t netnox_ssh_client_connect(netnox_ssh_client_t * client);
extern const char * netnox_ssh_client_get_server_ident(const netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_get_server_host_key_fingerprint(const netnox_ssh_client_t * client,
                                                                         uint8_t * out_fingerprint,
                                                                         uint32_t * inout_len);
extern netnox_return_t netnox_ssh_client_authenticate(netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_open_session(netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_exec(netnox_ssh_client_t * client,
                                              const char * command);
extern netnox_return_t netnox_ssh_client_request_shell_ex(netnox_ssh_client_t * client,
                                                          uint8_t request_pty);
extern netnox_return_t netnox_ssh_client_request_shell(netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_send_data(netnox_ssh_client_t * client,
                                                   const uint8_t * data,
                                                   uint32_t len);
extern netnox_return_t netnox_ssh_client_send_keepalive(netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_rekey(netnox_ssh_client_t * client);
extern netnox_return_t netnox_ssh_client_recv_data(netnox_ssh_client_t * client,
                                                   uint8_t * data,
                                                   uint32_t * len);
extern netnox_return_t netnox_ssh_client_get_remote_exit_status(const netnox_ssh_client_t * client,
                                                                uint32_t * out_status);
extern netnox_return_t netnox_ssh_client_close(netnox_ssh_client_t * client);

#endif
