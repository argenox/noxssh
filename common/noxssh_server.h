/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* @file noxssh_server.h
* @brief NoxSSH SSH-2 server session API (transport callbacks; one connection).
*/

#ifndef _NOXSSH_SERVER_H_
#define _NOXSSH_SERVER_H_

#include <stdint.h>
#include "noxssh_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Server session context (one accepted TCP/stream connection).
 *
 * I/O is supplied via @ref netnox_ssh_server_set_io_callbacks. Cryptographic
 * host identity is an Ed25519 key (RFC 8709 ssh-ed25519).
 */
typedef struct netnox_ssh_server
{
    netnox_ssh_transport_send_t send_cb;
    netnox_ssh_transport_recv_t recv_cb;
    void * io_user_data;

    char client_ident[NETNOX_SSH_MAX_IDENT_LEN + 1u];
    char server_ident[NETNOX_SSH_MAX_IDENT_LEN + 1u];

    uint8_t host_ed25519_sk[32];
    uint8_t host_ed25519_pk[32];
    uint8_t host_key_ready;

    /** Plain password accepted for any username (demo / lab use). Empty = no password auth. */
    char allowed_password[NETNOX_SSH_MAX_PASSWORD_LEN + 1u];

    uint8_t connected;
    uint8_t kexinit_exchanged;
    uint8_t userauth_service_ready;
    uint8_t connection_service_ready;
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

    /** Rekey scaffolding (RFC 4253 §9): incremented with encrypted payload bytes. */
    uint64_t encrypted_bytes_sent;
    uint64_t encrypted_bytes_recv;
    uint64_t rekey_threshold_bytes;
} netnox_ssh_server_t;

extern netnox_return_t netnox_ssh_server_init(netnox_ssh_server_t * server);
extern void netnox_ssh_server_set_io_callbacks(netnox_ssh_server_t * server,
                                               netnox_ssh_transport_send_t send_cb,
                                               netnox_ssh_transport_recv_t recv_cb,
                                               void * io_user_data);
extern netnox_return_t netnox_ssh_server_set_identification(netnox_ssh_server_t * server,
                                                          const char * server_ident);
/**
 * @brief Load host key from 32-byte Ed25519 seed (RFC 8032 private key format used by NoxTLS).
 */
extern netnox_return_t netnox_ssh_server_set_host_ed25519_seed(netnox_ssh_server_t * server,
                                                               const uint8_t secret_seed[32]);
extern netnox_return_t netnox_ssh_server_generate_host_ed25519_key(netnox_ssh_server_t * server);
extern netnox_return_t netnox_ssh_server_set_allowed_password(netnox_ssh_server_t * server,
                                                              const char * password);

/**
 * @brief Run full handshake and one interactive session (auth, channel, exec/shell requests).
 *
 * Blocks until the peer disconnects or a fatal protocol error. Exec requests run a
 * one-shot subprocess (stdout only bridged to the channel). Shell and SFTP subsystem
 * requests are rejected unless extended by platform adapters.
 */
extern netnox_return_t netnox_ssh_server_serve_one(netnox_ssh_server_t * server);

extern void netnox_ssh_server_reset(netnox_ssh_server_t * server);

#ifdef __cplusplus
}
#endif

#endif /* _NOXSSH_SERVER_H_ */
