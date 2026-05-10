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
* File:    noxssh_common.c
* Summary: NoxSSH common SSH protocol implementation
*
*/

/**
 * @file noxssh_common.c
 * @brief NoxSSH common SSH client protocol implementation.
 * @ingroup noxssh_common
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "noxssh_common.h"

/** @brief Parsed SSH debug level from NETNOX_SSH_DEBUG (0..3). */
static int netnox_ssh_debug_level(void)
{
    const char * env = getenv("NETNOX_SSH_DEBUG");
    int level = 0;

    if(env == NULL || env[0] == '\0') {
        return 0;
    }
    if(env[0] >= '1' && env[0] <= '3' && env[1] == '\0') {
        return (int)(env[0] - '0');
    }
    /* Backward compatibility: any non-empty value enables level 1. */
    level = atoi(env);
    if(level < 0) {
        level = 0;
    } else if(level > 3) {
        level = 3;
    } else if(level == 0) {
        level = 1;
    }
    return level;
}
#define SSH_DEBUG(fmt, ...) \
    do { if(netnox_ssh_debug_level() >= 1) (void)fprintf(stderr, "SSH_DEBUG: " fmt "\n", ##__VA_ARGS__); } while(0)
#define SSH_DEBUG2(fmt, ...) \
    do { if(netnox_ssh_debug_level() >= 2) (void)fprintf(stderr, "SSH_DEBUG: " fmt "\n", ##__VA_ARGS__); } while(0)
#define SSH_DEBUG3(fmt, ...) \
    do { if(netnox_ssh_debug_level() >= 3) (void)fprintf(stderr, "SSH_DEBUG: " fmt "\n", ##__VA_ARGS__); } while(0)

/** @brief Hex-dump first n bytes of buf to stderr when NETNOX_SSH_DEBUG is set (for key comparison). */
static void netnox_ssh_debug_hex(const char * label, const uint8_t * buf, uint32_t n)
{
    uint32_t i = 0u;
    if(netnox_ssh_debug_level() < 3 || buf == NULL || n == 0u) {
        return;
    }
    (void)fprintf(stderr, "SSH_DEBUG: %s (%u bytes): ", label, (unsigned)n);
    for(i = 0u; i < n && i < 32u; i++) {
        (void)fprintf(stderr, "%02x", (unsigned)buf[i]);
    }
    if(n > 32u) {
        (void)fprintf(stderr, "...");
    }
    (void)fprintf(stderr, "\n");
}

/** @brief Hex-dump up to max_bytes of buf (full dump, no truncation in output). */
static void netnox_ssh_debug_hex_full(const char * label, const uint8_t * buf, uint32_t n, uint32_t max_bytes)
{
    uint32_t i = 0u;
    uint32_t show = (n > max_bytes) ? max_bytes : n;
    if(netnox_ssh_debug_level() < 3 || buf == NULL || show == 0u) {
        return;
    }
    (void)fprintf(stderr, "SSH_DEBUG: %s (%u bytes): ", label, (unsigned)n);
    for(i = 0u; i < show; i++) {
        (void)fprintf(stderr, "%02x", (unsigned)buf[i]);
    }
    if(n > max_bytes) {
        (void)fprintf(stderr, "... (%u more)", (unsigned)(n - max_bytes));
    }
    (void)fprintf(stderr, "\n");
}
#include "../noxtls/noxtls-lib/pkc/x25519/noxtls_x25519.h"
#include "../noxtls/noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#include "../noxtls/noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "../noxtls/noxtls-lib/mdigest/noxtls_sha.h"
#include "../noxtls/noxtls-lib/encryption/aes/noxtls_aes.h"
#include "../noxtls/noxtls-lib/mdigest/noxtls_hash.h"

/** @brief CR byte value used by SSH identification framing. */
#define NETNOX_SSH_CHAR_CR ((char)'\r')
/** @brief LF byte value used by SSH identification framing. */
#define NETNOX_SSH_CHAR_LF ((char)'\n')
/** @brief Minimum SSH packet padding bytes. */
#define NETNOX_SSH_MIN_PADDING_LEN (4u)
/** @brief SSH packet block alignment prior to negotiated ciphers. */
#define NETNOX_SSH_PACKET_BLOCK_SIZE (8u)
/** @brief Size of KEXINIT random cookie. */
#define NETNOX_SSH_KEXINIT_COOKIE_LEN (16u)
/** @brief Max local buffer used to serialize one KEXINIT payload. */
#define NETNOX_SSH_KEXINIT_PAYLOAD_MAX_LEN (1024u)
/** @brief AES block size in bytes (SSH aes128-ctr). */
#define NETNOX_SSH_AES_BLOCK_LEN (16u)
/** @brief HMAC-SHA256 output length in bytes. */
#define NETNOX_SSH_MAC_LEN (32u)

/** @brief One-time seed guard for pseudo-random padding/cookie bytes. */
static uint8_t g_netnox_ssh_prng_seeded = 0u;

static netnox_return_t netnox_ssh_send_packet(netnox_ssh_client_t * client,
                                              const uint8_t * payload,
                                              uint32_t payload_len);
static netnox_return_t netnox_ssh_wait_for_message(netnox_ssh_client_t * client,
                                                   uint8_t expect_a,
                                                   uint8_t expect_b,
                                                   uint8_t * out_payload,
                                                   uint32_t out_payload_max,
                                                   uint32_t * out_payload_len);
static netnox_return_t netnox_ssh_handle_server_kexinit(netnox_ssh_client_t * client,
                                                        const uint8_t * server_kexinit,
                                                        uint32_t server_kexinit_len);
static netnox_return_t netnox_ssh_sha256(const uint8_t * data,
                                         uint32_t data_len,
                                         uint8_t * out_hash32);
static netnox_return_t netnox_ssh_verify_server_host_key_signature(const uint8_t * host_key_blob,
                                                                    uint32_t host_key_blob_len,
                                                                    const uint8_t * sig_blob,
                                                                    uint32_t sig_blob_len,
                                                                    const uint8_t * exchange_hash,
                                                                    uint32_t exchange_hash_len);
static netnox_return_t netnox_ssh_wait_userauth_result(netnox_ssh_client_t * client);

/**
 * @brief Compute HMAC-SHA256(key, data) into mac_out (32 bytes).
 * @internal
 */
static netnox_return_t netnox_ssh_hmac_sha256(const uint8_t * key,
                                              uint32_t key_len,
                                              const uint8_t * data,
                                              uint32_t data_len,
                                              uint8_t * mac_out)
{
    noxtls_sha_ctx_t ctx;
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner_hash[32];
    uint32_t i = 0u;

    if(key == NULL || data == NULL || mac_out == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(noxtls_sha_init(&ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    memset(ipad, 0x36, sizeof(ipad));
    memset(opad, 0x5C, sizeof(opad));
    if(key_len > 64u) {
        noxtls_sha_update(&ctx, (uint8_t *)key, key_len);
        noxtls_sha_finish(&ctx, inner_hash);
        key = inner_hash;
        key_len = 32u;
    }
    for(i = 0u; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    noxtls_sha_init(&ctx, NOXTLS_HASH_SHA_256);
    noxtls_sha_update(&ctx, ipad, 64u);
    noxtls_sha_update(&ctx, (uint8_t *)data, data_len);
    noxtls_sha_finish(&ctx, inner_hash);
    noxtls_sha_init(&ctx, NOXTLS_HASH_SHA_256);
    noxtls_sha_update(&ctx, opad, 64u);
    noxtls_sha_update(&ctx, inner_hash, 32u);
    noxtls_sha_finish(&ctx, mac_out);
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t netnox_ssh_sha256(const uint8_t * data,
                                         uint32_t data_len,
                                         uint8_t * out_hash32)
{
    noxtls_sha_ctx_t sha_ctx;

    if((data == NULL && data_len != 0u) || out_hash32 == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(noxtls_sha_init(&sha_ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(data_len > 0u && noxtls_sha_update(&sha_ctx, (uint8_t *)data, data_len) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(noxtls_sha_finish(&sha_ctx, out_hash32) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t netnox_ssh_verify_server_host_key_signature(const uint8_t * host_key_blob,
                                                                    uint32_t host_key_blob_len,
                                                                    const uint8_t * sig_blob,
                                                                    uint32_t sig_blob_len,
                                                                    const uint8_t * exchange_hash,
                                                                    uint32_t exchange_hash_len)
{
    uint32_t hk_off = 0u;
    uint32_t sig_off = 0u;
    const uint8_t * hk_alg = NULL;
    uint32_t hk_alg_len = 0u;
    const uint8_t * hk_e = NULL;
    uint32_t hk_e_len = 0u;
    const uint8_t * hk_n = NULL;
    uint32_t hk_n_len = 0u;
    const uint8_t * sig_alg = NULL;
    uint32_t sig_alg_len = 0u;
    const uint8_t * sig_data = NULL;
    uint32_t sig_data_len = 0u;
    uint8_t rsa_sig_norm[512];
    rsa_key_t rsa_key;
    noxtls_hash_algos_t rsa_hash = NOXTLS_HASH_SHA_256;
    noxtls_return_t rsa_rc = NOXTLS_RETURN_FAILED;
    rsa_key_size_t rsa_size = RSA_2048_BIT;
    uint32_t n_trim = 0u;
    uint32_t e_trim = 0u;
    static const char alg_ed25519[] = "ssh-ed25519";
    static const char alg_ssh_rsa[] = "ssh-rsa";
    static const char alg_rsa_sha2_256[] = "rsa-sha2-256";

    if(host_key_blob == NULL || host_key_blob_len == 0u ||
       sig_blob == NULL || sig_blob_len == 0u ||
       exchange_hash == NULL || exchange_hash_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_read_string_view(host_key_blob, host_key_blob_len, &hk_off, &hk_alg, &hk_alg_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("hostkey verify: failed to parse host key blob");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(sig_blob, sig_blob_len, &sig_off, &sig_alg, &sig_alg_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_payload_read_string_view(sig_blob, sig_blob_len, &sig_off, &sig_data, &sig_data_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("hostkey verify: failed to parse signature blob");
        return NETNOX_RETURN_FAILED;
    }

    if(hk_alg_len == (uint32_t)strlen(alg_ed25519) &&
       memcmp(hk_alg, alg_ed25519, (uint32_t)strlen(alg_ed25519)) == 0 &&
       sig_alg_len == (uint32_t)strlen(alg_ed25519) &&
       memcmp(sig_alg, alg_ed25519, (uint32_t)strlen(alg_ed25519)) == 0) {
        if(netnox_ssh_payload_read_string_view(host_key_blob, host_key_blob_len, &hk_off, &hk_e, &hk_e_len) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("hostkey verify: failed to parse ed25519 key bytes");
            return NETNOX_RETURN_FAILED;
        }
        if(hk_e_len != NOXTLS_ED25519_PUBLIC_KEY_SIZE || sig_data_len != NOXTLS_ED25519_SIGNATURE_SIZE) {
            SSH_DEBUG("hostkey verify: invalid ed25519 key/signature length (key=%u sig=%u)",
                      (unsigned)hk_e_len,
                      (unsigned)sig_data_len);
            return NETNOX_RETURN_FAILED;
        }
        if(noxtls_ed25519_verify(hk_e, exchange_hash, exchange_hash_len, sig_data) != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("hostkey verify: ed25519 signature invalid");
            return NETNOX_RETURN_FAILED;
        }
        SSH_DEBUG("hostkey verify: ed25519 signature valid");
        return NETNOX_RETURN_SUCCESS;
    }

    if(hk_alg_len == (uint32_t)strlen(alg_ssh_rsa) &&
       memcmp(hk_alg, alg_ssh_rsa, (uint32_t)strlen(alg_ssh_rsa)) == 0 &&
       ((sig_alg_len == (uint32_t)strlen(alg_rsa_sha2_256) &&
         memcmp(sig_alg, alg_rsa_sha2_256, (uint32_t)strlen(alg_rsa_sha2_256)) == 0) ||
        (sig_alg_len == (uint32_t)strlen(alg_ssh_rsa) &&
         memcmp(sig_alg, alg_ssh_rsa, (uint32_t)strlen(alg_ssh_rsa)) == 0))) {
        if(netnox_ssh_payload_read_string_view(host_key_blob, host_key_blob_len, &hk_off, &hk_e, &hk_e_len) != NETNOX_RETURN_SUCCESS ||
           netnox_ssh_payload_read_string_view(host_key_blob, host_key_blob_len, &hk_off, &hk_n, &hk_n_len) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("hostkey verify: failed to parse rsa key components");
            return NETNOX_RETURN_FAILED;
        }
        while(n_trim < hk_n_len && hk_n[n_trim] == 0u) {
            n_trim++;
        }
        while(e_trim < hk_e_len && hk_e[e_trim] == 0u) {
            e_trim++;
        }
        hk_n += n_trim;
        hk_n_len -= n_trim;
        hk_e += e_trim;
        hk_e_len -= e_trim;
        if(hk_n_len == 0u || hk_e_len == 0u) {
            SSH_DEBUG("hostkey verify: invalid rsa modulus/exponent");
            return NETNOX_RETURN_FAILED;
        }

        if(hk_n_len <= 128u) {
            rsa_size = RSA_1024_BIT;
        } else if(hk_n_len <= 256u) {
            rsa_size = RSA_2048_BIT;
        } else if(hk_n_len <= 384u) {
            rsa_size = RSA_3072_BIT;
        } else if(hk_n_len <= 512u) {
            rsa_size = RSA_4096_BIT;
        } else {
            SSH_DEBUG("hostkey verify: unsupported rsa modulus length: %u", (unsigned)hk_n_len);
            return NETNOX_RETURN_FAILED;
        }

        if(sig_alg_len == (uint32_t)strlen(alg_rsa_sha2_256)) {
            rsa_hash = NOXTLS_HASH_SHA_256;
        } else {
            rsa_hash = NOXTLS_HASH_SHA1;
        }

        if(noxtls_rsa_key_init(&rsa_key, rsa_size) != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("hostkey verify: rsa key init failed");
            return NETNOX_RETURN_FAILED;
        }
        if(hk_n_len > rsa_key.key_bytes || hk_e_len > rsa_key.key_bytes) {
            (void)noxtls_rsa_key_free(&rsa_key);
            SSH_DEBUG("hostkey verify: rsa key components exceed selected key size");
            return NETNOX_RETURN_FAILED;
        }
        memcpy(&rsa_key.n[rsa_key.key_bytes - hk_n_len], hk_n, hk_n_len);
        memcpy(&rsa_key.e[rsa_key.key_bytes - hk_e_len], hk_e, hk_e_len);

        if(sig_data_len > rsa_key.key_bytes) {
            (void)noxtls_rsa_key_free(&rsa_key);
            SSH_DEBUG("hostkey verify: rsa signature too large");
            return NETNOX_RETURN_FAILED;
        }
        memset(rsa_sig_norm, 0, sizeof(rsa_sig_norm));
        if(rsa_key.key_bytes > sizeof(rsa_sig_norm)) {
            (void)noxtls_rsa_key_free(&rsa_key);
            SSH_DEBUG("hostkey verify: rsa key bytes exceed local buffer");
            return NETNOX_RETURN_FAILED;
        }
        memcpy(&rsa_sig_norm[rsa_key.key_bytes - sig_data_len], sig_data, sig_data_len);
        rsa_rc = noxtls_rsa_verify(&rsa_key,
                                   exchange_hash,
                                   exchange_hash_len,
                                   rsa_sig_norm,
                                   rsa_key.key_bytes,
                                   rsa_hash);
        (void)noxtls_rsa_key_free(&rsa_key);
        if(rsa_rc != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("hostkey verify: rsa signature invalid");
            return NETNOX_RETURN_FAILED;
        }
        SSH_DEBUG("hostkey verify: rsa signature valid");
        return NETNOX_RETURN_SUCCESS;
    }

    SSH_DEBUG("hostkey verify: unsupported host key algorithm: %.*s",
              (int)hk_alg_len,
              (const char *)hk_alg);
    return NETNOX_RETURN_FAILED;
}

/**
 * @brief Increment a 16-byte big-endian counter by n_blocks (for AES-CTR).
 * @internal
 */
static void netnox_ssh_ctr_increment_blocks(uint8_t * counter_16, uint32_t n_blocks)
{
    int i = 0;
    uint64_t carry = (uint64_t)n_blocks;

    for(i = 15; i >= 0 && carry > 0u; i--) {
        carry += (uint64_t)counter_16[i];
        counter_16[i] = (uint8_t)(carry & 0xFFu);
        carry >>= 8;
    }
}

/**
 * @brief Copy C string to destination with null-termination.
 * @internal
 *
 * @param dst Destination output string buffer.
 * @param dst_len Destination buffer length in bytes.
 * @param src Source C string.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_BAD_PARAM on invalid input.
 */
static netnox_return_t netnox_ssh_copy_string(char * dst, uint16_t dst_len, const char * src)
{
    size_t src_len = 0u;

    if(dst == NULL || src == NULL || dst_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    src_len = strlen(src);
    if(src_len > (size_t)(dst_len - 1u)) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Send a full buffer through configured transport callback.
 * @internal
 *
 * @param client SSH client context.
 * @param data Bytes to send.
 * @param len Number of bytes to send.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on I/O failure.
 */
static netnox_return_t netnox_ssh_send_all(netnox_ssh_client_t * client, const uint8_t * data, uint32_t len)
{
    uint32_t sent_total = 0u;

    if(client == NULL || data == NULL || client->send_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    while(sent_total < len) {
        int32_t sent = client->send_cb(client->io_user_data, data + sent_total, len - sent_total);
        if(sent <= 0) {
            return NETNOX_RETURN_FAILED;
        }
        sent_total += (uint32_t)sent;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Receive an exact number of bytes through configured transport callback.
 * @internal
 *
 * @param client SSH client context.
 * @param data Destination byte buffer.
 * @param len Number of bytes to receive.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on I/O failure.
 */
static netnox_return_t netnox_ssh_recv_exact(netnox_ssh_client_t * client, uint8_t * data, uint32_t len)
{
    uint32_t recv_total = 0u;

    if(client == NULL || data == NULL || client->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    while(recv_total < len) {
        int32_t got = client->recv_cb(client->io_user_data, data + recv_total, len - recv_total);
        if(got <= 0) {
            SSH_DEBUG("recv_exact: recv_cb returned %d (received %u of %u bytes); 0=closed, negative=error",
                      (int)got, (unsigned)recv_total, (unsigned)len);
            if(recv_total == 0u && client->key_exchange_complete != 0u) {
                SSH_DEBUG("(server closed after we sent encrypted data: decrypt or MAC likely failed on its side; check key derivation RFC 4253 sec.7.2, RFC 8731 sec.3.1)");
            }
            if(recv_total > 0u) {
                netnox_ssh_debug_hex_full("recv_exact partial buffer", data, recv_total, 64u);
            }
            return NETNOX_RETURN_FAILED;
        }
        recv_total += (uint32_t)got;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Receive one line from transport until LF and store trimmed result.
 * @internal
 *
 * @param client SSH client context.
 * @param out Output string buffer.
 * @param out_len Output buffer length.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on I/O error or overflow.
 */
static netnox_return_t netnox_ssh_recv_line(netnox_ssh_client_t * client, char * out, uint16_t out_len)
{
    uint16_t used = 0u;

    if(client == NULL || out == NULL || out_len == 0u || client->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    while(used < (uint16_t)(out_len - 1u)) {
        int32_t rc = 0;
        uint8_t ch = 0u;

        rc = client->recv_cb(client->io_user_data, &ch, 1u);
        if(rc <= 0) {
            return NETNOX_RETURN_FAILED;
        }

        if((char)ch == NETNOX_SSH_CHAR_LF) {
            break;
        }

        if((char)ch != NETNOX_SSH_CHAR_CR) {
            out[used++] = (char)ch;
        }
    }

    /* Line too long (e.g. long banner): discard remainder until LF, return empty line so caller can skip. */
    if(used == (uint16_t)(out_len - 1u)) {
        uint8_t ch = 0u;
        while(1) {
            int32_t rc = client->recv_cb(client->io_user_data, &ch, 1u);
            if(rc <= 0) {
                return NETNOX_RETURN_FAILED;
            }
            if((char)ch == NETNOX_SSH_CHAR_LF) {
                break;
            }
        }
        out[0] = '\0';
        return NETNOX_RETURN_SUCCESS;
    }

    out[used] = '\0';
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Return whether a line is an SSH identification string.
 * @internal
 *
 * @param line Candidate line.
 *
 * @return 1 if line starts with "SSH-", otherwise 0.
 */
static int netnox_ssh_is_ident_line(const char * line)
{
    if(line == NULL) {
        return 0;
    }

    return (strncmp(line, "SSH-", 4u) == 0) ? 1 : 0;
}

/**
 * @brief Write 32-bit unsigned integer in network byte order.
 * @internal
 *
 * @param out 4-byte destination.
 * @param value Value to encode.
 */
static void netnox_ssh_write_u32_be(uint8_t * out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xFFu);
    out[1] = (uint8_t)((value >> 16) & 0xFFu);
    out[2] = (uint8_t)((value >> 8) & 0xFFu);
    out[3] = (uint8_t)(value & 0xFFu);
}

/**
 * @brief Read 32-bit unsigned integer from network byte order.
 * @internal
 *
 * @param in 4-byte encoded value.
 *
 * @return Decoded host-order value.
 */
static uint32_t netnox_ssh_read_u32_be(const uint8_t * in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

/**
 * @brief Fill output bytes using simple PRNG suitable for non-key material placeholders.
 * @internal
 *
 * @param out Output byte buffer.
 * @param len Number of bytes to fill.
 */
static void netnox_ssh_fill_random(uint8_t * out, uint32_t len)
{
    uint32_t i = 0u;

    if(out == NULL || len == 0u) {
        return;
    }

    if(g_netnox_ssh_prng_seeded == 0u) {
        srand((unsigned int)time(NULL));
        g_netnox_ssh_prng_seeded = 1u;
    }

    for(i = 0u; i < len; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
}

/**
 * @brief Append SSH name-list field (uint32 length + bytes) to a payload buffer.
 * @internal
 *
 * @param payload Destination payload buffer.
 * @param payload_len In/out payload used length.
 * @param payload_max Payload capacity.
 * @param list Name-list text (comma-separated).
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_BAD_PARAM on invalid input.
 */
static netnox_return_t netnox_ssh_payload_append_namelist(uint8_t * payload,
                                                          uint32_t * payload_len,
                                                          uint32_t payload_max,
                                                          const char * list)
{
    uint32_t list_len = 0u;

    if(payload == NULL || payload_len == NULL || list == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    list_len = (uint32_t)strlen(list);
    if((*payload_len + 4u + list_len) > payload_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    netnox_ssh_write_u32_be(&payload[*payload_len], list_len);
    *payload_len += 4u;
    if(list_len > 0u) {
        memcpy(&payload[*payload_len], list, list_len);
        *payload_len += list_len;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Append a single byte field to payload.
 * @internal
 *
 * @param payload Destination payload buffer.
 * @param payload_len In/out payload used length.
 * @param payload_max Payload capacity.
 * @param value Byte value to append.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_BAD_PARAM on overflow.
 */
static netnox_return_t netnox_ssh_payload_append_u8(uint8_t * payload,
                                                    uint32_t * payload_len,
                                                    uint32_t payload_max,
                                                    uint8_t value)
{
    if(payload == NULL || payload_len == NULL || (*payload_len + 1u) > payload_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    payload[*payload_len] = value;
    *payload_len += 1u;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Append a 32-bit unsigned integer to payload.
 * @internal
 */
static netnox_return_t netnox_ssh_payload_append_u32(uint8_t * payload,
                                                     uint32_t * payload_len,
                                                     uint32_t payload_max,
                                                     uint32_t value)
{
    if(payload == NULL || payload_len == NULL || (*payload_len + 4u) > payload_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    netnox_ssh_write_u32_be(&payload[*payload_len], value);
    *payload_len += 4u;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Append an SSH string field (uint32 length + bytes) to payload.
 * @internal
 */
static netnox_return_t netnox_ssh_payload_append_string(uint8_t * payload,
                                                        uint32_t * payload_len,
                                                        uint32_t payload_max,
                                                        const uint8_t * str_data,
                                                        uint32_t str_len)
{
    if(payload == NULL || payload_len == NULL || (str_len > 0u && str_data == NULL)) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if((*payload_len + 4u + str_len) > payload_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    netnox_ssh_write_u32_be(&payload[*payload_len], str_len);
    *payload_len += 4u;
    if(str_len > 0u) {
        memcpy(&payload[*payload_len], str_data, str_len);
        *payload_len += str_len;
    }
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Read a 32-bit field from payload at offset.
 * @internal
 */
static netnox_return_t netnox_ssh_payload_read_u32(const uint8_t * payload,
                                                   uint32_t payload_len,
                                                   uint32_t * offset,
                                                   uint32_t * out_value)
{
    if(payload == NULL || offset == NULL || out_value == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if((*offset + 4u) > payload_len) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    *out_value = netnox_ssh_read_u32_be(&payload[*offset]);
    *offset += 4u;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Read an SSH string field view from payload at offset.
 * @internal
 */
static netnox_return_t netnox_ssh_payload_read_string_view(const uint8_t * payload,
                                                           uint32_t payload_len,
                                                           uint32_t * offset,
                                                           const uint8_t ** out_data,
                                                           uint32_t * out_len)
{
    uint32_t str_len = 0u;

    if(payload == NULL || offset == NULL || out_data == NULL || out_len == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_read_u32(payload, payload_len, offset, &str_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if((*offset + str_len) > payload_len) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    *out_data = &payload[*offset];
    *out_len = str_len;
    *offset += str_len;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Return whether a required token exists in a comma-separated SSH namelist.
 * @internal
 *
 * @param list Pointer to namelist bytes (not null-terminated).
 * @param list_len Namelist length.
 * @param token Null-terminated required token.
 *
 * @return 1 when token is found, otherwise 0.
 */
static int netnox_ssh_namelist_contains(const uint8_t * list, uint32_t list_len, const char * token)
{
    uint32_t start = 0u;
    uint32_t token_len = 0u;

    if(list == NULL || token == NULL) {
        return 0;
    }
    token_len = (uint32_t)strlen(token);
    if(token_len == 0u) {
        return 0;
    }

    while(start < list_len) {
        uint32_t end = start;
        while(end < list_len && list[end] != (uint8_t)',') {
            end++;
        }
        if((end - start) == token_len && memcmp(&list[start], token, token_len) == 0) {
            return 1;
        }
        if(end >= list_len) {
            break;
        }
        start = end + 1u;
    }
    return 0;
}

/**
 * @brief Parse and validate required algorithm names from server SSH_MSG_KEXINIT.
 * @internal
 *
 * @param payload Server KEXINIT payload bytes.
 * @param payload_len Payload length.
 *
 * @return NETNOX_RETURN_SUCCESS if required algorithms are offered, otherwise NETNOX_RETURN_FAILED.
 */
static netnox_return_t netnox_ssh_validate_server_kexinit(const uint8_t * payload, uint32_t payload_len)
{
    uint32_t offset = 0u;
    const uint8_t * field = NULL;
    uint32_t field_len = 0u;

    if(payload == NULL || payload_len < (1u + NETNOX_SSH_KEXINIT_COOKIE_LEN)) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(payload[0] != NETNOX_SSH_MSG_KEXINIT) {
        return NETNOX_RETURN_FAILED;
    }

    offset = 1u + NETNOX_SSH_KEXINIT_COOKIE_LEN;

    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_KEX_ALG) == 0) {
        SSH_DEBUG("kexinit: required kex algorithm not offered: %s", NETNOX_SSH_REQUIRED_KEX_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_HOST_KEY_ALG) == 0) {
        SSH_DEBUG("kexinit: required host key algorithm not offered: %s", NETNOX_SSH_REQUIRED_HOST_KEY_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_CIPHER_ALG) == 0) {
        SSH_DEBUG("kexinit: required c2s cipher not offered: %s", NETNOX_SSH_REQUIRED_CIPHER_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_CIPHER_ALG) == 0) {
        SSH_DEBUG("kexinit: required s2c cipher not offered: %s", NETNOX_SSH_REQUIRED_CIPHER_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_MAC_ALG) == 0) {
        SSH_DEBUG("kexinit: required c2s MAC not offered: %s", NETNOX_SSH_REQUIRED_MAC_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_MAC_ALG) == 0) {
        SSH_DEBUG("kexinit: required s2c MAC not offered: %s", NETNOX_SSH_REQUIRED_MAC_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_COMPRESSION_ALG) == 0) {
        SSH_DEBUG("kexinit: required c2s compression not offered: %s", NETNOX_SSH_REQUIRED_COMPRESSION_ALG);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS ||
       netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_COMPRESSION_ALG) == 0) {
        SSH_DEBUG("kexinit: required s2c compression not offered: %s", NETNOX_SSH_REQUIRED_COMPRESSION_ALG);
        return NETNOX_RETURN_FAILED;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Append raw bytes into a growable hash-input buffer.
 * @internal
 */
static netnox_return_t netnox_ssh_buf_append(uint8_t * out,
                                             uint32_t * out_len,
                                             uint32_t out_max,
                                             const uint8_t * in,
                                             uint32_t in_len)
{
    if(out == NULL || out_len == NULL || (in_len > 0u && in == NULL)) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if((*out_len + in_len) > out_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(in_len > 0u) {
        memcpy(&out[*out_len], in, in_len);
        *out_len += in_len;
    }
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Append SSH mpint from a fixed-length big-endian unsigned byte string.
 * @internal
 */
static netnox_return_t netnox_ssh_buf_append_mpint_be(uint8_t * out,
                                                      uint32_t * out_len,
                                                      uint32_t out_max,
                                                      const uint8_t * in,
                                                      uint32_t in_len)
{
    uint32_t first = 0u;
    uint32_t value_len = 0u;
    uint8_t zero = 0u;

    if(out == NULL || out_len == NULL || in == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    while(first < in_len && in[first] == 0u) {
        first++;
    }
    if(first == in_len) {
        return netnox_ssh_payload_append_u32(out, out_len, out_max, 0u);
    }

    value_len = in_len - first;
    if((in[first] & 0x80u) != 0u) {
        if(netnox_ssh_payload_append_u32(out, out_len, out_max, value_len + 1u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_BAD_PARAM;
        }
        if(netnox_ssh_buf_append(out, out_len, out_max, &zero, 1u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_BAD_PARAM;
        }
    } else {
        if(netnox_ssh_payload_append_u32(out, out_len, out_max, value_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_BAD_PARAM;
        }
    }

    return netnox_ssh_buf_append(out, out_len, out_max, &in[first], value_len);
}

/**
 * @brief Append SSH mpint for a fixed 32-byte value (curve25519 K per RFC 8731 section 3.1).
 * @internal
 *
 * RFC 8731: "The 32 or 56 bytes of X are converted into K by interpreting the octets as
 * an unsigned fixed-length integer encoded in network byte order." Some servers
 * (e.g. Dropbear) encode K as a fixed 32-byte mpint (no leading-zero stripping).
 * Use this for exchange hash and key derivation when shared secret is 32 bytes.
 */
static netnox_return_t netnox_ssh_buf_append_mpint_be_32(uint8_t * out,
                                                         uint32_t * out_len,
                                                         uint32_t out_max,
                                                         const uint8_t * in)
{
    uint8_t zero = 0u;

    if(out == NULL || out_len == NULL || in == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if((*out_len + 4u + 33u) > out_max) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    /* If high bit of first byte is set, prepend 0x00 for positive mpint (RFC 4251). */
    if((in[0] & 0x80u) != 0u) {
        netnox_ssh_write_u32_be(&out[*out_len], 33u);
        *out_len += 4u;
        out[*out_len] = zero;
        *out_len += 1u;
        memcpy(&out[*out_len], in, 32u);
        *out_len += 32u;
    } else {
        netnox_ssh_write_u32_be(&out[*out_len], 32u);
        *out_len += 4u;
        memcpy(&out[*out_len], in, 32u);
        *out_len += 32u;
    }
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Compute SSH exchange hash H for curve25519-sha256 (RFC 5656 section 4, RFC 8731).
 * @internal
 *
 * H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
 * All as SSH strings (length-prefix) except K as mpint. session_id = H (first KEX).
 */
static netnox_return_t netnox_ssh_compute_exchange_hash(netnox_ssh_client_t * client,
                                                        const uint8_t * host_key_blob,
                                                        uint32_t host_key_blob_len,
                                                        const uint8_t * client_pub,
                                                        uint32_t client_pub_len,
                                                        const uint8_t * server_pub,
                                                        uint32_t server_pub_len,
                                                        const uint8_t * shared_secret_raw,
                                                        uint32_t shared_secret_raw_len,
                                                        uint8_t out_hash[32])
{
    uint8_t h_input[4096];
    uint32_t h_input_len = 0u;
    noxtls_sha_ctx_t sha_ctx;
    noxtls_return_t noxrc = NOXTLS_RETURN_FAILED;

    if(client == NULL || host_key_blob == NULL || client_pub == NULL || server_pub == NULL ||
       shared_secret_raw == NULL || out_hash == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        (const uint8_t *)client->client_ident,
                                        (uint32_t)strlen(client->client_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        (const uint8_t *)client->server_ident,
                                        (uint32_t)strlen(client->server_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        client->kexinit_client_payload,
                                        client->kexinit_client_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        client->kexinit_server_payload,
                                        client->kexinit_server_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        host_key_blob,
                                        host_key_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        client_pub,
                                        client_pub_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        server_pub,
                                        server_pub_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append_mpint_be(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                      shared_secret_raw,
                                      shared_secret_raw_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    noxrc = noxtls_sha_init(&sha_ctx, NOXTLS_HASH_SHA_256);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    noxrc = noxtls_sha_update(&sha_ctx, h_input, h_input_len);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    noxrc = noxtls_sha_finish(&sha_ctx, out_hash);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Derive one SSH key block using RFC 4253 section 7.2.
 * @internal
 *
 * RFC 4253: "Initial IV client to server: HASH(K || H || \"A\" || session_id)"
 * and similarly B,C,D,E,F, where K is mpint. We therefore use mpint(K) by default.
 * Compatibility toggle: set NETNOX_SSH_KEY_DERIV_MPINT=0 to force raw 32-byte K.
 * Extension: subsequent = HASH(K || H || all output so far).
 */
static netnox_return_t netnox_ssh_derive_key_block(netnox_ssh_client_t * client,
                                                   uint8_t selector,
                                                   uint8_t * out,
                                                   uint32_t out_len)
{
    uint8_t seed[1024];
    uint32_t seed_len = 0u;
    uint8_t digest[32];
    noxtls_sha_ctx_t sha_ctx;
    noxtls_return_t noxrc = NOXTLS_RETURN_FAILED;
    uint32_t produced = 0u;
    uint32_t take = 0u;
    int use_mpint = 1;
    uint8_t k_enc[4u + 33u];
    uint32_t k_enc_len = 0u;
    if(client == NULL || out == NULL || out_len == 0u || client->session_id_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    {
        const char * env = getenv("NETNOX_SSH_KEY_DERIV_MPINT");
        if(env != NULL && env[0] == '0' && env[1] == '\0') {
            use_mpint = 0;
            SSH_DEBUG("key derivation: using raw K for key block (NETNOX_SSH_KEY_DERIV_MPINT=0)");
        } else {
            SSH_DEBUG("key derivation: using mpint(K) for key block");
        }
    }

    if(use_mpint) {
        if(netnox_ssh_buf_append_mpint_be(k_enc, &k_enc_len, (uint32_t)sizeof(k_enc),
                                          client->shared_secret_raw,
                                          (uint32_t)sizeof(client->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), k_enc, k_enc_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
    } else {
        /* Compatibility fallback for non-RFC peers: raw 32-byte K for key block. */
        if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed),
                                 client->shared_secret_raw,
                                 (uint32_t)sizeof(client->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed),
                             client->session_id, client->session_id_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), &selector, 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed),
                             client->session_id, client->session_id_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    noxrc = noxtls_sha_init(&sha_ctx, NOXTLS_HASH_SHA_256);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    noxrc = noxtls_sha_update(&sha_ctx, seed, seed_len);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    noxrc = noxtls_sha_finish(&sha_ctx, digest);
    if(noxrc != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    take = (out_len < (uint32_t)sizeof(digest)) ? out_len : (uint32_t)sizeof(digest);
    memcpy(out, digest, take);
    produced = take;

    while(produced < out_len) {
        uint8_t cont_in[2048];
        uint32_t cont_len = 0u;

        if(use_mpint) {
            k_enc_len = 0u;
            if(netnox_ssh_buf_append_mpint_be(k_enc, &k_enc_len, (uint32_t)sizeof(k_enc),
                                              client->shared_secret_raw,
                                              (uint32_t)sizeof(client->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in), k_enc, k_enc_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
        } else {
            if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in),
                                    client->shared_secret_raw,
                                    (uint32_t)sizeof(client->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
        }
        if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in),
                                client->session_id, client->session_id_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in), out, produced) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }

        noxrc = noxtls_sha_init(&sha_ctx, NOXTLS_HASH_SHA_256);
        if(noxrc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        noxrc = noxtls_sha_update(&sha_ctx, cont_in, cont_len);
        if(noxrc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        noxrc = noxtls_sha_finish(&sha_ctx, digest);
        if(noxrc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }

        take = (out_len - produced) < (uint32_t)sizeof(digest) ? (out_len - produced) : (uint32_t)sizeof(digest);
        memcpy(out + produced, digest, take);
        produced += take;
    }

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Derive initial IV, cipher, and MAC key material after NEWKEYS.
 * @internal
 */
static netnox_return_t netnox_ssh_derive_transport_keys(netnox_ssh_client_t * client)
{
    if(client == NULL || client->session_id_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'A', client->c2s_iv, (uint32_t)sizeof(client->c2s_iv)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'B', client->s2c_iv, (uint32_t)sizeof(client->s2c_iv)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'C', client->c2s_key, (uint32_t)sizeof(client->c2s_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'D', client->s2c_key, (uint32_t)sizeof(client->s2c_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'E', client->c2s_mac_key, (uint32_t)sizeof(client->c2s_mac_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_derive_key_block(client, (uint8_t)'F', client->s2c_mac_key, (uint32_t)sizeof(client->s2c_mac_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->c2s_counter, client->c2s_iv, NETNOX_SSH_AES_BLOCK_LEN);
    memcpy(client->s2c_counter, client->s2c_iv, NETNOX_SSH_AES_BLOCK_LEN);
    /* Debug: dump first bytes of derived material for comparison with other implementations. */
    netnox_ssh_debug_hex("session_id (H)", client->session_id, client->session_id_len);
    netnox_ssh_debug_hex("c2s_iv", client->c2s_iv, (uint32_t)sizeof(client->c2s_iv));
    netnox_ssh_debug_hex("c2s_key", client->c2s_key, (uint32_t)sizeof(client->c2s_key));
    netnox_ssh_debug_hex("c2s_mac_key", client->c2s_mac_key, (uint32_t)sizeof(client->c2s_mac_key));
    netnox_ssh_debug_hex("s2c_iv", client->s2c_iv, (uint32_t)sizeof(client->s2c_iv));
    netnox_ssh_debug_hex("s2c_key", client->s2c_key, (uint32_t)sizeof(client->s2c_key));

    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Perform curve25519 ECDH key exchange messages and NEWKEYS exchange.
 * @internal
 */
static netnox_return_t netnox_ssh_perform_curve25519_kex(netnox_ssh_client_t * client)
{
    uint8_t priv[32];
    uint8_t pub_c[32];
    uint8_t shared_raw[32];
    uint8_t kex_init_payload[128];
    uint32_t kex_init_payload_len = 0u;
    uint8_t reply_payload[2048];
    uint32_t reply_payload_len = 0u;
    uint32_t off = 1u;
    const uint8_t * host_key_blob = NULL;
    uint32_t host_key_blob_len = 0u;
    const uint8_t * pub_s = NULL;
    uint32_t pub_s_len = 0u;
    const uint8_t * sig_h = NULL;
    uint32_t sig_h_len = 0u;
    uint8_t newkeys_payload[1];

    if(client == NULL || client->kexinit_exchanged == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(noxtls_x25519_generate_key(priv, pub_c) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_payload_append_u8(kex_init_payload,
                                    &kex_init_payload_len,
                                    (uint32_t)sizeof(kex_init_payload),
                                    NETNOX_SSH_MSG_KEX_ECDH_INIT) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(kex_init_payload,
                                        &kex_init_payload_len,
                                        (uint32_t)sizeof(kex_init_payload),
                                        pub_c,
                                        (uint32_t)sizeof(pub_c)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_send_packet(client, kex_init_payload, kex_init_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_KEX_ECDH_REPLY,
                                   0xFFu,
                                   reply_payload,
                                   (uint32_t)sizeof(reply_payload),
                                   &reply_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(reply_payload_len == 0u || reply_payload[0] != NETNOX_SSH_MSG_KEX_ECDH_REPLY) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(reply_payload, reply_payload_len, &off, &host_key_blob, &host_key_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(reply_payload, reply_payload_len, &off, &pub_s, &pub_s_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(reply_payload, reply_payload_len, &off, &sig_h, &sig_h_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(sig_h_len == 0u || pub_s_len != 32u) {
        return NETNOX_RETURN_FAILED;
    }
    if(host_key_blob_len == 0u || host_key_blob_len > NETNOX_SSH_MAX_HOST_KEY_BLOB_LEN) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->server_host_key_blob, host_key_blob, host_key_blob_len);
    client->server_host_key_blob_len = host_key_blob_len;
    if(netnox_ssh_sha256(host_key_blob,
                         host_key_blob_len,
                         client->server_host_key_fingerprint) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    client->server_host_key_ready = 1u;
    if(noxtls_x25519_shared_secret(priv, pub_s, shared_raw) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_compute_exchange_hash(client,
                                        host_key_blob,
                                        host_key_blob_len,
                                        pub_c,
                                        (uint32_t)sizeof(pub_c),
                                        pub_s,
                                        pub_s_len,
                                        shared_raw,
                                        (uint32_t)sizeof(shared_raw),
                                        client->session_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_verify_server_host_key_signature(host_key_blob,
                                                   host_key_blob_len,
                                                   sig_h,
                                                   sig_h_len,
                                                   client->session_id,
                                                   32u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    client->session_id_len = 32u;
    memcpy(client->shared_secret_raw, shared_raw, sizeof(shared_raw));

    /* Optional: dump KEX inputs to JSON for comparison with scripts/ref_ssh_keys.py */
    if(getenv("NETNOX_SSH_DUMP_KEYS") != NULL) {
        const char * dump_path = getenv("NOXSSH_DUMP_FILE");
        if(dump_path == NULL || dump_path[0] == '\0') {
            dump_path = "noxssh_kex_dump.json";
        }
        FILE * dump_f = fopen(dump_path, "w");
        if(dump_f == NULL && strcmp(dump_path, "noxssh_kex_dump.json") != 0) {
            SSH_DEBUG("failed to create %s (check path/write permission), trying default", dump_path);
            dump_path = "noxssh_kex_dump.json";
            dump_f = fopen(dump_path, "w");
        }
        if(dump_f == NULL) {
            SSH_DEBUG("failed to create %s (check path/write permission)", dump_path);
        } else {
            uint32_t i = 0u;
            fprintf(dump_f, "{\n  \"client_ident\": \"");
            for(i = 0u; client->client_ident[i] != '\0'; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)(unsigned char)client->client_ident[i]);
            }
            fprintf(dump_f, "\",\n  \"server_ident\": \"");
            for(i = 0u; client->server_ident[i] != '\0'; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)(unsigned char)client->server_ident[i]);
            }
            fprintf(dump_f, "\",\n  \"kexinit_client_payload\": \"");
            for(i = 0u; i < client->kexinit_client_payload_len; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)client->kexinit_client_payload[i]);
            }
            fprintf(dump_f, "\",\n  \"kexinit_server_payload\": \"");
            for(i = 0u; i < client->kexinit_server_payload_len; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)client->kexinit_server_payload[i]);
            }
            fprintf(dump_f, "\",\n  \"host_key_blob\": \"");
            for(i = 0u; i < host_key_blob_len; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)host_key_blob[i]);
            }
            fprintf(dump_f, "\",\n  \"client_pub\": \"");
            for(i = 0u; i < (uint32_t)sizeof(pub_c); i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)pub_c[i]);
            }
            fprintf(dump_f, "\",\n  \"server_pub\": \"");
            for(i = 0u; i < pub_s_len; i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)pub_s[i]);
            }
            fprintf(dump_f, "\",\n  \"shared_secret_raw\": \"");
            for(i = 0u; i < (uint32_t)sizeof(shared_raw); i++) {
                (void)fprintf(dump_f, "%02x", (unsigned)shared_raw[i]);
            }
            fprintf(dump_f, "\"\n}\n");
            (void)fclose(dump_f);
            SSH_DEBUG("dumped KEX inputs to %s (run: python scripts/ref_ssh_keys.py %s)", dump_path, dump_path);
        }
    }

    newkeys_payload[0] = NETNOX_SSH_MSG_NEWKEYS;
    if(netnox_ssh_send_packet(client, newkeys_payload, 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_NEWKEYS,
                                   0xFFu,
                                   reply_payload,
                                   (uint32_t)sizeof(reply_payload),
                                   &reply_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(reply_payload_len == 0u || reply_payload[0] != NETNOX_SSH_MSG_NEWKEYS) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_derive_transport_keys(client) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    client->key_exchange_complete = 1u;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Build SSH_MSG_KEXINIT payload bytes.
 * @internal
 *
 * @param payload Output payload buffer.
 * @param payload_len In/out payload length.
 * @param payload_max Output capacity.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on format/space errors.
 */
static netnox_return_t netnox_ssh_build_kexinit_payload(uint8_t * payload,
                                                        uint32_t * payload_len,
                                                        uint32_t payload_max)
{
    uint32_t i = 0u;
    netnox_return_t rc = NETNOX_RETURN_SUCCESS;

    if(payload == NULL || payload_len == NULL || payload_max < (1u + NETNOX_SSH_KEXINIT_COOKIE_LEN)) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    payload[0] = NETNOX_SSH_MSG_KEXINIT;
    *payload_len = 1u;

    netnox_ssh_fill_random(&payload[*payload_len], NETNOX_SSH_KEXINIT_COOKIE_LEN);
    *payload_len += NETNOX_SSH_KEXINIT_COOKIE_LEN;

    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_KEX_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_HOST_KEY_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_CIPHER_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_CIPHER_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_MAC_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_MAC_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_COMPRESSION_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_COMPRESSION_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, "");
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, "");
    if(rc != NETNOX_RETURN_SUCCESS) { return NETNOX_RETURN_FAILED; }

    if((*payload_len + 1u + 4u) > payload_max) {
        return NETNOX_RETURN_FAILED;
    }

    payload[*payload_len] = 0u; /* first_kex_packet_follows */
    *payload_len += 1u;
    netnox_ssh_write_u32_be(&payload[*payload_len], 0u); /* reserved */
    *payload_len += 4u;

    for(i = 0u; i < *payload_len; i++) {
        (void)payload[i];
    }
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Send one SSH binary packet with protocol-compliant framing and padding.
 * @internal
 *
 * @param client SSH client context.
 * @param payload Payload bytes to frame.
 * @param payload_len Payload length.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on errors.
 */
static netnox_return_t netnox_ssh_send_packet(netnox_ssh_client_t * client,
                                              const uint8_t * payload,
                                              uint32_t payload_len)
{
    uint32_t padding_len = NETNOX_SSH_MIN_PADDING_LEN;
    uint32_t packet_len = 0u;
    uint32_t plain_len = 0u;
    uint32_t n_blocks = 0u;
    uint32_t block_size = 0u; /* cipher block size or 8 for unencrypted (RFC 4253 §6) */
    uint8_t plain[4u + NETNOX_SSH_MAX_PACKET_LEN];
    uint8_t enc[4u + NETNOX_SSH_MAX_PACKET_LEN];
    uint8_t mac_buf[NETNOX_SSH_MAC_LEN];
    uint8_t seq_be[4];
    netnox_return_t send_rc = NETNOX_RETURN_FAILED;
    noxtls_return_t aes_rc = NOXTLS_RETURN_SUCCESS;

    if(client == NULL || payload == NULL || payload_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    /* RFC 4253 §6: total length must be multiple of (cipher block size or 8, whichever larger). */
    block_size = (client->key_exchange_complete != 0u) ? NETNOX_SSH_AES_BLOCK_LEN : NETNOX_SSH_PACKET_BLOCK_SIZE;
    while(((1u + payload_len + padding_len + 4u) % block_size) != 0u) {
        padding_len++;
    }

    packet_len = 1u + payload_len + padding_len;
    plain_len = 4u + packet_len;
    if(packet_len > NETNOX_SSH_MAX_PACKET_LEN) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    netnox_ssh_write_u32_be(&plain[0], packet_len);
    plain[4] = (uint8_t)padding_len;
    memcpy(&plain[5], payload, payload_len);
    netnox_ssh_fill_random(&plain[5u + payload_len], padding_len);

    if(client->key_exchange_complete != 0u) {
        uint8_t mac_input[4u + 4u + NETNOX_SSH_MAX_PACKET_LEN];

        /* RFC 4253 sec 6.4: mac = MAC(key, sequence_number || unencrypted_packet).
         * unencrypted_packet = packet_length || padding_length || payload || padding (plain).
         * OpenSSH mac.c mac_compute() uses same: put_u32(seqno) then data. */
        netnox_ssh_write_u32_be(seq_be, client->send_seq);
        memcpy(mac_input, seq_be, 4u);
        memcpy(mac_input + 4u, plain, plain_len);
        if(netnox_ssh_hmac_sha256(client->c2s_mac_key,
                                  (uint32_t)sizeof(client->c2s_mac_key),
                                  mac_input,
                                  4u + plain_len,
                                  mac_buf) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_debug_hex_full("send plain (packet_len|pad_len|payload..)", plain, plain_len, 48u);
        netnox_ssh_debug_hex_full("send seq_be (MAC input)", seq_be, 4u, 4u);
        netnox_ssh_debug_hex("send c2s_counter (IV for this packet)", client->c2s_counter, NETNOX_SSH_AES_BLOCK_LEN);
        /* RFC 4253 sec 6.3: encrypt packet_length || padding_length || payload || padding.
         * RFC 4344 SDCTR: IV as 16-byte big-endian counter; we increment LSB (byte 15) up. */
        aes_rc = aes_encrypt_ctr(client->c2s_key,
                                 plain,
                                 plain_len,
                                 client->c2s_counter,
                                 enc,
                                 AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("send_packet(enc): AES encrypt failed");
            return NETNOX_RETURN_FAILED;
        }
        n_blocks = (plain_len + NETNOX_SSH_AES_BLOCK_LEN - 1u) / NETNOX_SSH_AES_BLOCK_LEN;
        netnox_ssh_ctr_increment_blocks(client->c2s_counter, n_blocks);
        SSH_DEBUG3("send_packet(enc): sending %u encrypted + %u MAC bytes, send_seq=%u payload_type=%u",
                  (unsigned)plain_len, (unsigned)NETNOX_SSH_MAC_LEN, (unsigned)client->send_seq,
                  (unsigned)(plain_len > 5u ? plain[5] : 0xFFu));
        netnox_ssh_debug_hex_full("send encrypted", enc, plain_len, 48u);
        netnox_ssh_debug_hex_full("send MAC", mac_buf, NETNOX_SSH_MAC_LEN, 32u);
        /* Send [pending New Keys if any] + encrypted + MAC in one TCP write when possible (PuTTY/OpenSSH do New Keys + first encrypted in one segment). */
        {
            uint8_t combined[128];
            uint32_t enc_mac_len = plain_len + NETNOX_SSH_MAC_LEN;
            uint32_t total = client->pending_newkeys_len + enc_mac_len;
            if(total > 0u && total <= (uint32_t)sizeof(combined)) {
                uint32_t off = 0u;
                if(client->pending_newkeys_len > 0u) {
                    memcpy(combined, client->pending_newkeys, client->pending_newkeys_len);
                    off = client->pending_newkeys_len;
                    client->pending_newkeys_len = 0u;
                }
                memcpy(combined + off, enc, plain_len);
                memcpy(combined + off + plain_len, mac_buf, NETNOX_SSH_MAC_LEN);
                if(netnox_ssh_send_all(client, combined, total) != NETNOX_RETURN_SUCCESS) {
                    SSH_DEBUG("send_packet(enc): send_all(newkeys+enc+mac) failed");
                    return NETNOX_RETURN_FAILED;
                }
            } else {
                if(client->pending_newkeys_len > 0u) {
                    if(netnox_ssh_send_all(client, client->pending_newkeys, client->pending_newkeys_len) != NETNOX_RETURN_SUCCESS) {
                        SSH_DEBUG("send_packet(enc): send_all(pending_newkeys) failed");
                        return NETNOX_RETURN_FAILED;
                    }
                    client->pending_newkeys_len = 0u;
                }
                if(enc_mac_len <= (uint32_t)sizeof(combined)) {
                    memcpy(combined, enc, plain_len);
                    memcpy(combined + plain_len, mac_buf, NETNOX_SSH_MAC_LEN);
                    if(netnox_ssh_send_all(client, combined, enc_mac_len) != NETNOX_RETURN_SUCCESS) {
                        SSH_DEBUG("send_packet(enc): send_all(enc+mac) failed");
                        return NETNOX_RETURN_FAILED;
                    }
                } else {
                    if(netnox_ssh_send_all(client, enc, plain_len) != NETNOX_RETURN_SUCCESS) {
                        SSH_DEBUG("send_packet(enc): send_all(enc) failed");
                        return NETNOX_RETURN_FAILED;
                    }
                    if(netnox_ssh_send_all(client, mac_buf, NETNOX_SSH_MAC_LEN) != NETNOX_RETURN_SUCCESS) {
                        SSH_DEBUG("send_packet(enc): send_all(mac) failed");
                        return NETNOX_RETURN_FAILED;
                    }
                }
            }
        }
        client->send_seq++;
        return NETNOX_RETURN_SUCCESS;
    }

    /* Unencrypted: NEWKEYS (single byte 21). Send immediately so server sees it as a complete packet
     * before any encrypted data; some servers (e.g. Dropbear) can reject when NEWKEYS+encrypted
     * are in one TCP segment. */
    if(payload_len == 1u && payload[0] == NETNOX_SSH_MSG_NEWKEYS) {
        send_rc = netnox_ssh_send_all(client, plain, plain_len);
        if(send_rc == NETNOX_RETURN_SUCCESS) {
            client->send_seq++;
        }
        return send_rc;
    }
    send_rc = netnox_ssh_send_all(client, plain, plain_len);
    if(send_rc == NETNOX_RETURN_SUCCESS) {
        client->send_seq++;
    }
    return send_rc;
}

/**
 * @brief Receive one SSH binary packet and return its payload.
 * @internal
 *
 * @param client SSH client context.
 * @param payload_out Output payload buffer.
 * @param payload_max Payload buffer capacity.
 * @param payload_len_out Output payload length.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on decode/I/O errors.
 */
static netnox_return_t netnox_ssh_recv_packet(netnox_ssh_client_t * client,
                                              uint8_t * payload_out,
                                              uint32_t payload_max,
                                              uint32_t * payload_len_out)
{
    uint8_t len_buf[4];
    uint8_t packet[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t packet_len = 0u;
    uint32_t payload_len = 0u;
    uint8_t padding_len = 0u;

    if(client == NULL || payload_out == NULL || payload_len_out == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(client->key_exchange_complete != 0u) {
        uint8_t enc[4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint8_t plain[4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint8_t mac_buf[NETNOX_SSH_MAC_LEN];
        uint8_t mac_input[4u + 4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint32_t plain_len = 0u;
        uint32_t n_blocks = 0u;
        noxtls_return_t aes_rc = NOXTLS_RETURN_SUCCESS;

        SSH_DEBUG3("recv_packet(enc): waiting for first block (16 bytes), recv_seq=%u", (unsigned)client->recv_seq);
        if(netnox_ssh_recv_exact(client, enc, NETNOX_SSH_AES_BLOCK_LEN) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): recv first block (16 bytes) failed");
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_debug_hex("recv s2c_counter (IV for this packet)", client->s2c_counter, NETNOX_SSH_AES_BLOCK_LEN);
        netnox_ssh_debug_hex_full("recv first block (ciphertext)", enc, NETNOX_SSH_AES_BLOCK_LEN, 16u);
        aes_rc = aes_encrypt_ctr(client->s2c_key,
                                 enc,
                                 NETNOX_SSH_AES_BLOCK_LEN,
                                 client->s2c_counter,
                                 plain,
                                 AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): first block decrypt failed");
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_ctr_increment_blocks(client->s2c_counter, 1u);

        packet_len = netnox_ssh_read_u32_be(&plain[0]);
        SSH_DEBUG3("recv_packet(enc): first block decrypted, packet_len=%u", (unsigned)packet_len);
        netnox_ssh_debug_hex_full("recv first block (plaintext)", plain, NETNOX_SSH_AES_BLOCK_LEN, 16u);
        if(packet_len < (1u + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN) {
            SSH_DEBUG("recv_packet(enc): invalid packet_len %u (min %u max %u)",
                      (unsigned)packet_len, (unsigned)(1u + NETNOX_SSH_MIN_PADDING_LEN), (unsigned)NETNOX_SSH_MAX_PACKET_LEN);
            return NETNOX_RETURN_FAILED;
        }
        plain_len = 4u + packet_len;
        if(netnox_ssh_recv_exact(client, &enc[NETNOX_SSH_AES_BLOCK_LEN], plain_len - NETNOX_SSH_AES_BLOCK_LEN) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): recv rest of packet failed");
            return NETNOX_RETURN_FAILED;
        }
        aes_rc = aes_encrypt_ctr(client->s2c_key,
                                 &enc[NETNOX_SSH_AES_BLOCK_LEN],
                                 plain_len - NETNOX_SSH_AES_BLOCK_LEN,
                                 client->s2c_counter,
                                 &plain[NETNOX_SSH_AES_BLOCK_LEN],
                                 AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): second chunk decrypt failed");
            return NETNOX_RETURN_FAILED;
        }
        n_blocks = (plain_len + NETNOX_SSH_AES_BLOCK_LEN - 1u) / NETNOX_SSH_AES_BLOCK_LEN;
        netnox_ssh_ctr_increment_blocks(client->s2c_counter, n_blocks - 1u);

        if(netnox_ssh_recv_exact(client, mac_buf, NETNOX_SSH_MAC_LEN) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): recv MAC failed");
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_debug_hex_full("recv MAC (received)", mac_buf, NETNOX_SSH_MAC_LEN, 32u);
        /* RFC 4253 section 6.4: verify MAC(recv_seq || decrypted_packet) == received mac. */
        netnox_ssh_write_u32_be(mac_input, client->recv_seq);
        memcpy(mac_input + 4u, plain, plain_len);
        if(netnox_ssh_hmac_sha256(client->s2c_mac_key,
                                  (uint32_t)sizeof(client->s2c_mac_key),
                                  mac_input,
                                  4u + plain_len,
                                  mac_input) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("recv_packet(enc): HMAC compute failed");
            return NETNOX_RETURN_FAILED;
        }
        if(memcmp(mac_input, mac_buf, NETNOX_SSH_MAC_LEN) != 0) {
            SSH_DEBUG("recv_packet(enc): MAC verification failed (recv_seq=%u)", (unsigned)client->recv_seq);
            netnox_ssh_debug_hex_full("recv MAC (expected)", mac_input, NETNOX_SSH_MAC_LEN, 32u);
            netnox_ssh_debug_hex_full("recv plain (full for MAC input)", plain, plain_len, 64u);
            return NETNOX_RETURN_FAILED;
        }
        client->recv_seq++;

        padding_len = plain[4];
        if(padding_len < NETNOX_SSH_MIN_PADDING_LEN || (uint32_t)padding_len >= packet_len) {
            return NETNOX_RETURN_FAILED;
        }
        payload_len = packet_len - 1u - (uint32_t)padding_len;
        if(payload_len > payload_max) {
            return NETNOX_RETURN_FAILED;
        }
        if(payload_len > 0u) {
            memcpy(payload_out, &plain[5], payload_len);
        }
        *payload_len_out = payload_len;
        return NETNOX_RETURN_SUCCESS;
    }

    if(netnox_ssh_recv_exact(client, len_buf, sizeof(len_buf)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    packet_len = netnox_ssh_read_u32_be(len_buf);
    if(packet_len < (1u + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_recv_exact(client, packet, packet_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    padding_len = packet[0];
    if(padding_len < NETNOX_SSH_MIN_PADDING_LEN) {
        return NETNOX_RETURN_FAILED;
    }
    if((uint32_t)padding_len >= packet_len) {
        return NETNOX_RETURN_FAILED;
    }

    payload_len = packet_len - 1u - (uint32_t)padding_len;
    if(payload_len > payload_max) {
        return NETNOX_RETURN_FAILED;
    }

    if(payload_len > 0u) {
        memcpy(payload_out, &packet[1], payload_len);
    }
    *payload_len_out = payload_len;
    client->recv_seq++;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Exchange SSH_MSG_KEXINIT packets with peer.
 * @internal
 *
 * @param client SSH client context after identification exchange.
 *
 * @return NETNOX_RETURN_SUCCESS on success, NETNOX_RETURN_FAILED on protocol/I/O errors.
 */
static netnox_return_t netnox_ssh_exchange_kexinit(netnox_ssh_client_t * client)
{
    uint8_t tx_payload[NETNOX_SSH_KEXINIT_PAYLOAD_MAX_LEN];
    uint8_t rx_payload[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t tx_payload_len = 0u;
    uint32_t rx_payload_len = 0u;

    if(client == NULL || client->connected == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    SSH_DEBUG("KEX: building and sending KEXINIT");
    if(netnox_ssh_build_kexinit_payload(tx_payload,
                                        &tx_payload_len,
                                        (uint32_t)sizeof(tx_payload)) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("KEX: build_kexinit_payload failed");
        return NETNOX_RETURN_FAILED;
    }
    if(tx_payload_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        SSH_DEBUG("KEX: tx_payload_len too large");
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->kexinit_client_payload, tx_payload, tx_payload_len);
    client->kexinit_client_payload_len = tx_payload_len;

    if(netnox_ssh_send_packet(client, tx_payload, tx_payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("KEX: send_packet failed");
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_recv_packet(client,
                              rx_payload,
                              (uint32_t)sizeof(rx_payload),
                              &rx_payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("KEX: recv_packet failed");
        return NETNOX_RETURN_FAILED;
    }

    if(rx_payload_len == 0u || rx_payload[0] != NETNOX_SSH_MSG_KEXINIT) {
        SSH_DEBUG("KEX: unexpected msg type %u (len=%u)", (unsigned)(rx_payload_len > 0u ? rx_payload[0] : 0u), (unsigned)rx_payload_len);
        return NETNOX_RETURN_FAILED;
    }
    if(rx_payload_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        SSH_DEBUG("KEX: server KEXINIT too long");
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->kexinit_server_payload, rx_payload, rx_payload_len);
    client->kexinit_server_payload_len = rx_payload_len;
    if(netnox_ssh_validate_server_kexinit(rx_payload, rx_payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("KEX: validate_server_kexinit failed");
        return NETNOX_RETURN_FAILED;
    }

    client->kexinit_exchanged = 1u;
    SSH_DEBUG("KEX: performing Curve25519 KEX");
    return netnox_ssh_perform_curve25519_kex(client);
}

static netnox_return_t netnox_ssh_handle_server_kexinit(netnox_ssh_client_t * client,
                                                        const uint8_t * server_kexinit,
                                                        uint32_t server_kexinit_len)
{
    uint8_t tx_payload[NETNOX_SSH_KEXINIT_PAYLOAD_MAX_LEN];
    uint32_t tx_payload_len = 0u;

    if(client == NULL || server_kexinit == NULL || server_kexinit_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(server_kexinit[0] != NETNOX_SSH_MSG_KEXINIT) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(server_kexinit_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        SSH_DEBUG("rekey(server-init): server KEXINIT too long");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_validate_server_kexinit(server_kexinit, server_kexinit_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("rekey(server-init): validate_server_kexinit failed");
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->kexinit_server_payload, server_kexinit, server_kexinit_len);
    client->kexinit_server_payload_len = server_kexinit_len;

    if(netnox_ssh_build_kexinit_payload(tx_payload,
                                        &tx_payload_len,
                                        (uint32_t)sizeof(tx_payload)) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("rekey(server-init): build_kexinit_payload failed");
        return NETNOX_RETURN_FAILED;
    }
    if(tx_payload_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        SSH_DEBUG("rekey(server-init): local KEXINIT too long");
        return NETNOX_RETURN_FAILED;
    }
    memcpy(client->kexinit_client_payload, tx_payload, tx_payload_len);
    client->kexinit_client_payload_len = tx_payload_len;
    if(netnox_ssh_send_packet(client, tx_payload, tx_payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("rekey(server-init): send local KEXINIT failed");
        return NETNOX_RETURN_FAILED;
    }
    client->kexinit_exchanged = 1u;
    SSH_DEBUG("rekey(server-init): performing Curve25519 KEX");
    return netnox_ssh_perform_curve25519_kex(client);
}

/**
 * @brief Receive packets until one of two expected message IDs is observed.
 * @internal
 *
 * @param client SSH client context.
 * @param expect_a First expected message ID.
 * @param expect_b Second expected message ID (or 0xFF when unused).
 * @param out_payload Output payload buffer.
 * @param out_payload_max Output capacity.
 * @param out_payload_len Output payload length.
 *
 * @return NETNOX_RETURN_SUCCESS on expected message, NETNOX_RETURN_FAILED on protocol/I/O error.
 */
static netnox_return_t netnox_ssh_wait_for_message(netnox_ssh_client_t * client,
                                                   uint8_t expect_a,
                                                   uint8_t expect_b,
                                                   uint8_t * out_payload,
                                                   uint32_t out_payload_max,
                                                   uint32_t * out_payload_len)
{
    uint32_t i = 0u;
    uint8_t rx_payload[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t rx_payload_len = 0u;

    if(client == NULL || out_payload == NULL || out_payload_len == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    for(i = 0u; i < 32u; i++) {
        if(netnox_ssh_recv_packet(client,
                                  rx_payload,
                                  (uint32_t)sizeof(rx_payload),
                                  &rx_payload_len) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("wait_for_message: recv_packet failed at iteration %u", (unsigned)i);
            return NETNOX_RETURN_FAILED;
        }
        if(rx_payload_len == 0u) {
            continue;
        }
        if(rx_payload[0] == NETNOX_SSH_MSG_KEXINIT) {
            SSH_DEBUG("wait_for_message: handling server-initiated KEXINIT");
            if(netnox_ssh_handle_server_kexinit(client, rx_payload, rx_payload_len) != NETNOX_RETURN_SUCCESS) {
                SSH_DEBUG("wait_for_message: server-initiated rekey failed");
                return NETNOX_RETURN_FAILED;
            }
            continue;
        }
        if(rx_payload[0] == expect_a || rx_payload[0] == expect_b) {
            if(rx_payload_len > out_payload_max) {
                SSH_DEBUG("wait_for_message: expected msg %u too large for output buffer (%u > %u)",
                          (unsigned)rx_payload[0],
                          (unsigned)rx_payload_len,
                          (unsigned)out_payload_max);
                return NETNOX_RETURN_FAILED;
            }
            memcpy(out_payload, rx_payload, rx_payload_len);
            *out_payload_len = rx_payload_len;
            return NETNOX_RETURN_SUCCESS;
        }
        SSH_DEBUG("wait_for_message: got msg %u (expect %u or %u)",
                  (unsigned)rx_payload[0],
                  (unsigned)expect_a,
                  (unsigned)expect_b);
    }

    SSH_DEBUG("wait_for_message: max iterations reached");
    return NETNOX_RETURN_FAILED;
}

/**
 * @brief Send SSH service request for given service string.
 * @internal
 */
static netnox_return_t netnox_ssh_send_service_request(netnox_ssh_client_t * client, const char * service)
{
    uint8_t payload[128];
    uint32_t payload_len = 0u;

    if(client == NULL || service == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_SERVICE_REQUEST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload,
                                        &payload_len,
                                        (uint32_t)sizeof(payload),
                                        (const uint8_t *)service,
                                        (uint32_t)strlen(service)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return netnox_ssh_send_packet(client, payload, payload_len);
}

/**
 * @brief Perform service request/accept for ssh-userauth.
 * @internal
 */
static netnox_return_t netnox_ssh_negotiate_userauth_service(netnox_ssh_client_t * client)
{
    uint8_t payload[256];
    uint32_t payload_len = 0u;
    uint32_t offset = 1u;
    const uint8_t * svc = NULL;
    uint32_t svc_len = 0u;

    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    SSH_DEBUG("negotiate_userauth: sending service request ssh-userauth");
    if(netnox_ssh_send_service_request(client, NETNOX_SSH_SERVICE_USERAUTH) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("negotiate_userauth: send_service_request failed");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_SERVICE_ACCEPT,
                                   0xFFu,
                                   payload,
                                   (uint32_t)sizeof(payload),
                                   &payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("negotiate_userauth: wait_for_message SERVICE_ACCEPT failed");
        return NETNOX_RETURN_FAILED;
    }
    if(payload[0] != NETNOX_SSH_MSG_SERVICE_ACCEPT) {
        SSH_DEBUG("negotiate_userauth: unexpected message %u", (unsigned)payload[0]);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &svc, &svc_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(svc_len != strlen(NETNOX_SSH_SERVICE_USERAUTH) ||
       memcmp(svc, NETNOX_SSH_SERVICE_USERAUTH, svc_len) != 0) {
        return NETNOX_RETURN_FAILED;
    }

    client->userauth_service_ready = 1u;
    return NETNOX_RETURN_SUCCESS;
}

/**
 * @brief Send password-based userauth request.
 * @internal
 */
static netnox_return_t netnox_ssh_send_userauth_password(netnox_ssh_client_t * client)
{
    uint8_t payload[512];
    uint32_t payload_len = 0u;

    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_USERAUTH_REQUEST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)client->username, (uint32_t)strlen(client->username)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_SERVICE_CONNECTION, (uint32_t)strlen(NETNOX_SSH_SERVICE_CONNECTION)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_AUTH_METHOD_PASSWORD, (uint32_t)strlen(NETNOX_SSH_AUTH_METHOD_PASSWORD)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), 0u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)client->password, (uint32_t)strlen(client->password)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    return netnox_ssh_send_packet(client, payload, payload_len);
}

/**
 * @brief Send Ed25519 publickey userauth request (with signature).
 * @internal
 */
static netnox_return_t netnox_ssh_send_userauth_publickey_ed25519(netnox_ssh_client_t * client)
{
    uint8_t payload[1024];
    uint8_t pubkey_blob[256];
    uint8_t sig_blob[256];
    uint8_t to_sign[1400];
    uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE];
    uint32_t payload_len = 0u;
    uint32_t pubkey_blob_len = 0u;
    uint32_t sig_blob_len = 0u;
    uint32_t to_sign_len = 0u;
    uint32_t req_no_sig_len = 0u;

    if(client == NULL || client->has_ed25519_key == 0u || client->session_id_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_append_string(pubkey_blob, &pubkey_blob_len, (uint32_t)sizeof(pubkey_blob),
                                        (const uint8_t *)NETNOX_SSH_KEYALG_ED25519,
                                        (uint32_t)strlen(NETNOX_SSH_KEYALG_ED25519)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(pubkey_blob, &pubkey_blob_len, (uint32_t)sizeof(pubkey_blob),
                                        client->ed25519_public_key,
                                        (uint32_t)sizeof(client->ed25519_public_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_USERAUTH_REQUEST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)client->username, (uint32_t)strlen(client->username)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_SERVICE_CONNECTION, (uint32_t)strlen(NETNOX_SSH_SERVICE_CONNECTION)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_AUTH_METHOD_PUBLICKEY, (uint32_t)strlen(NETNOX_SSH_AUTH_METHOD_PUBLICKEY)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_KEYALG_ED25519, (uint32_t)strlen(NETNOX_SSH_KEYALG_ED25519)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        pubkey_blob, pubkey_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    req_no_sig_len = payload_len;

    if(netnox_ssh_payload_append_string(to_sign, &to_sign_len, (uint32_t)sizeof(to_sign),
                                        client->session_id, client->session_id_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(to_sign_len + req_no_sig_len > (uint32_t)sizeof(to_sign)) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(&to_sign[to_sign_len], payload, req_no_sig_len);
    to_sign_len += req_no_sig_len;

    if(noxtls_ed25519_sign(client->ed25519_private_key,
                           to_sign,
                           to_sign_len,
                           signature) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_payload_append_string(sig_blob, &sig_blob_len, (uint32_t)sizeof(sig_blob),
                                        (const uint8_t *)NETNOX_SSH_KEYALG_ED25519,
                                        (uint32_t)strlen(NETNOX_SSH_KEYALG_ED25519)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(sig_blob, &sig_blob_len, (uint32_t)sizeof(sig_blob),
                                        signature, (uint32_t)sizeof(signature)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        sig_blob, sig_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return netnox_ssh_send_packet(client, payload, payload_len);
}

static netnox_return_t netnox_ssh_wait_userauth_result(netnox_ssh_client_t * client)
{
    uint8_t payload[512];
    uint32_t payload_len = 0u;

    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_USERAUTH_SUCCESS,
                                   NETNOX_SSH_MSG_USERAUTH_FAILURE,
                                   payload,
                                   (uint32_t)sizeof(payload),
                                   &payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("authenticate: wait_for_message failed (timeout or recv error)");
        return NETNOX_RETURN_FAILED;
    }
    if(payload_len == 0u) {
        SSH_DEBUG("authenticate: empty payload");
        return NETNOX_RETURN_FAILED;
    }
    SSH_DEBUG("authenticate: got message type %u", (unsigned)payload[0]);
    if(payload[0] == NETNOX_SSH_MSG_USERAUTH_SUCCESS) {
        client->authenticated = 1u;
        return NETNOX_RETURN_SUCCESS;
    }
    if(payload[0] == NETNOX_SSH_MSG_USERAUTH_FAILURE) {
        SSH_DEBUG("authenticate: server sent USERAUTH_FAILURE");
        return NETNOX_RETURN_AUTH_REJECTED;
    }
    SSH_DEBUG("authenticate: unexpected message type %u", (unsigned)payload[0]);
    return NETNOX_RETURN_FAILED;
}

/**
 * @brief Send session channel open request.
 * @internal
 */
static netnox_return_t netnox_ssh_send_channel_open_session(netnox_ssh_client_t * client)
{
    uint8_t payload[256];
    uint32_t payload_len = 0u;

    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_OPEN) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_CHANNEL_TYPE_SESSION, (uint32_t)strlen(NETNOX_SSH_CHANNEL_TYPE_SESSION)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->local_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->local_window_size) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    return netnox_ssh_send_packet(client, payload, payload_len);
}

netnox_return_t netnox_ssh_client_init(netnox_ssh_client_t * client, netnox_interface_t * itf, uint16_t port)
{
    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    memset(client, 0, sizeof(*client));
    client->itf = itf;
    client->port = (port == 0u) ? NETNOX_SSH_DEFAULT_PORT : port;

    return netnox_ssh_copy_string(client->client_ident,
                                  (uint16_t)sizeof(client->client_ident),
                                  NETNOX_SSH_DEFAULT_CLIENT_IDENT);
}

void netnox_ssh_client_set_io_callbacks(netnox_ssh_client_t * client,
                                        netnox_ssh_transport_send_t send_cb,
                                        netnox_ssh_transport_recv_t recv_cb,
                                        void * io_user_data)
{
    if(client == NULL) {
        return;
    }

    client->send_cb = send_cb;
    client->recv_cb = recv_cb;
    client->io_user_data = io_user_data;
}

netnox_return_t netnox_ssh_client_set_identification(netnox_ssh_client_t * client, const char * client_ident)
{
    if(client == NULL || client_ident == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    return netnox_ssh_copy_string(client->client_ident,
                                  (uint16_t)sizeof(client->client_ident),
                                  client_ident);
}

netnox_return_t netnox_ssh_client_set_target(netnox_ssh_client_t * client,
                                             const char * username,
                                             const char * host)
{
    netnox_return_t rc = NETNOX_RETURN_SUCCESS;

    if(client == NULL || username == NULL || host == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    rc = netnox_ssh_copy_string(client->username, (uint16_t)sizeof(client->username), username);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return rc;
    }

    return netnox_ssh_copy_string(client->host, (uint16_t)sizeof(client->host), host);
}

netnox_return_t netnox_ssh_client_set_password(netnox_ssh_client_t * client, const char * password)
{
    if(client == NULL || password == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    return netnox_ssh_copy_string(client->password, (uint16_t)sizeof(client->password), password);
}

netnox_return_t netnox_ssh_client_set_ed25519_private_key(netnox_ssh_client_t * client,
                                                          const uint8_t private_key[32])
{
    if(client == NULL || private_key == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    memcpy(client->ed25519_private_key, private_key, 32u);
    if(noxtls_ed25519_public_key(client->ed25519_private_key, client->ed25519_public_key) != NOXTLS_RETURN_SUCCESS) {
        client->has_ed25519_key = 0u;
        return NETNOX_RETURN_FAILED;
    }
    client->has_ed25519_key = 1u;
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_connect(netnox_ssh_client_t * client)
{
    uint8_t banner_index = 0u;
    char tx_ident[NETNOX_SSH_MAX_IDENT_LEN + 3u];

    if(client == NULL || client->send_cb == NULL || client->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(strlen(client->client_ident) == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(snprintf(tx_ident, sizeof(tx_ident), "%s\r\n", client->client_ident) <= 0) {
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_send_all(client, (const uint8_t *)tx_ident, (uint32_t)strlen(tx_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    SSH_DEBUG("sent ident: %s", client->client_ident);

    for(banner_index = 0u; banner_index < NETNOX_SSH_MAX_BANNER_LINES; banner_index++) {
        netnox_return_t rc = netnox_ssh_recv_line(client, client->server_ident, (uint16_t)sizeof(client->server_ident));
        if(rc != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("ident recv_line failed (banner_index=%u)", (unsigned)banner_index);
            return rc;
        }
        SSH_DEBUG("recv line[%u]: \"%s\"", (unsigned)banner_index, client->server_ident[0] != '\0' ? client->server_ident : "(empty/long line skipped)");

        if(netnox_ssh_is_ident_line(client->server_ident) != 0) {
            client->connected = 1u;
            return netnox_ssh_exchange_kexinit(client);
        }
    }

    SSH_DEBUG("no SSH- ident line after %u lines", (unsigned)NETNOX_SSH_MAX_BANNER_LINES);
    return NETNOX_RETURN_FAILED;
}

const char * netnox_ssh_client_get_server_ident(const netnox_ssh_client_t * client)
{
    if(client == NULL || client->server_ident[0] == '\0') {
        return NULL;
    }

    return client->server_ident;
}

netnox_return_t netnox_ssh_client_get_server_host_key_fingerprint(const netnox_ssh_client_t * client,
                                                                  uint8_t * out_fingerprint,
                                                                  uint32_t * inout_len)
{
    if(client == NULL || out_fingerprint == NULL || inout_len == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->server_host_key_ready == 0u) {
        return NETNOX_RETURN_FAILED;
    }
    if(*inout_len < NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN) {
        *inout_len = NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN;
        return NETNOX_RETURN_BAD_PARAM;
    }
    memcpy(out_fingerprint, client->server_host_key_fingerprint, NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN);
    *inout_len = NETNOX_SSH_HOST_KEY_FINGERPRINT_LEN;
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_authenticate(netnox_ssh_client_t * client)
{
    netnox_return_t auth_rc = NETNOX_RETURN_FAILED;
    uint8_t attempted = 0u;

    SSH_DEBUG("authenticate: connected=%u kex=%u key_complete=%u user=%s",
              (unsigned)client->connected,
              (unsigned)client->kexinit_exchanged,
              (unsigned)client->key_exchange_complete,
              client->username);

    if(client == NULL || client->connected == 0u || client->kexinit_exchanged == 0u || client->key_exchange_complete == 0u) {
        SSH_DEBUG("authenticate: failed preconditions (need connected, kex, key_complete)");
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->username[0] == '\0') {
        SSH_DEBUG("authenticate: missing username");
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->userauth_service_ready == 0u) {
        SSH_DEBUG("authenticate: requesting ssh-userauth service");
        if(netnox_ssh_negotiate_userauth_service(client) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("authenticate: negotiate_userauth_service failed");
            return NETNOX_RETURN_FAILED;
        }
        SSH_DEBUG("authenticate: ssh-userauth service accepted");
    }
    if(client->has_ed25519_key != 0u) {
        attempted = 1u;
        SSH_DEBUG("authenticate: sending publickey(ed25519) userauth request");
        if(netnox_ssh_send_userauth_publickey_ed25519(client) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("authenticate: send_userauth_publickey_ed25519 failed");
            return NETNOX_RETURN_FAILED;
        }
        auth_rc = netnox_ssh_wait_userauth_result(client);
        if(auth_rc == NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_SUCCESS;
        }
        if(auth_rc != NETNOX_RETURN_AUTH_REJECTED) {
            return NETNOX_RETURN_FAILED;
        }
        SSH_DEBUG("authenticate: publickey rejected, trying next method if available");
    }
    if(client->password[0] != '\0') {
        attempted = 1u;
        SSH_DEBUG("authenticate: sending password userauth request");
        if(netnox_ssh_send_userauth_password(client) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("authenticate: send_userauth_password failed");
            return NETNOX_RETURN_FAILED;
        }
        auth_rc = netnox_ssh_wait_userauth_result(client);
        if(auth_rc == NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_SUCCESS;
        }
        if(auth_rc == NETNOX_RETURN_AUTH_REJECTED) {
            return NETNOX_RETURN_AUTH_REJECTED;
        }
        return NETNOX_RETURN_FAILED;
    }
    if(attempted == 0u) {
        SSH_DEBUG("authenticate: no configured auth method (need ed25519 key and/or password)");
        return NETNOX_RETURN_BAD_PARAM;
    }
    return NETNOX_RETURN_AUTH_REJECTED;
}

netnox_return_t netnox_ssh_client_open_session(netnox_ssh_client_t * client)
{
    uint8_t payload[512];
    uint32_t payload_len = 0u;
    uint32_t offset = 1u;
    uint32_t recipient_channel = 0u;
    uint32_t sender_channel = 0u;
    uint32_t initial_window = 0u;
    uint32_t max_packet = 0u;

    if(client == NULL || client->connected == 0u || client->kexinit_exchanged == 0u ||
       client->key_exchange_complete == 0u || client->authenticated == 0u) {
        SSH_DEBUG("open_session: bad state (client=%p connected=%u kexinit=%u key_complete=%u auth=%u)",
                  (void *)client,
                  (unsigned)(client != NULL ? client->connected : 0u),
                  (unsigned)(client != NULL ? client->kexinit_exchanged : 0u),
                  (unsigned)(client != NULL ? client->key_exchange_complete : 0u),
                  (unsigned)(client != NULL ? client->authenticated : 0u));
        return NETNOX_RETURN_BAD_PARAM;
    }
    client->local_channel_id = 0u;
    client->local_window_size = NETNOX_SSH_CHANNEL_WINDOW_SIZE;

    if(netnox_ssh_send_channel_open_session(client) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: send CHANNEL_OPEN(session) failed");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                                   NETNOX_SSH_MSG_CHANNEL_OPEN_FAILURE,
                                   payload,
                                   (uint32_t)sizeof(payload),
                                   &payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: wait_for_message CHANNEL_OPEN_CONFIRMATION/FAILURE failed");
        return NETNOX_RETURN_FAILED;
    }
    if(payload_len == 0u) {
        SSH_DEBUG("open_session: empty response payload");
        return NETNOX_RETURN_FAILED;
    }
    if(payload[0] == NETNOX_SSH_MSG_CHANNEL_OPEN_FAILURE) {
        SSH_DEBUG("open_session: server returned CHANNEL_OPEN_FAILURE");
        return NETNOX_RETURN_FAILED;
    }
    if(payload[0] != NETNOX_SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
        SSH_DEBUG("open_session: unexpected response type %u", (unsigned)payload[0]);
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &recipient_channel) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: failed parsing recipient_channel");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &sender_channel) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: failed parsing sender_channel");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &initial_window) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: failed parsing initial_window");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &max_packet) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("open_session: failed parsing max_packet");
        return NETNOX_RETURN_FAILED;
    }

    if(recipient_channel != client->local_channel_id) {
        SSH_DEBUG("open_session: recipient_channel mismatch (got=%u expected=%u)",
                  (unsigned)recipient_channel,
                  (unsigned)client->local_channel_id);
        return NETNOX_RETURN_FAILED;
    }
    client->remote_channel_id = sender_channel;
    client->remote_window_size = initial_window;
    client->remote_max_packet_size = max_packet;
    client->channel_open = 1u;
    SSH_DEBUG("open_session: success local=%u remote=%u win=%u maxpkt=%u",
              (unsigned)client->local_channel_id,
              (unsigned)client->remote_channel_id,
              (unsigned)client->remote_window_size,
              (unsigned)client->remote_max_packet_size);
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_exec(netnox_ssh_client_t * client, const char * command)
{
    uint8_t payload[1024];
    uint32_t payload_len = 0u;
    uint8_t rsp[256];
    uint32_t rsp_len = 0u;

    if(client == NULL || command == NULL || client->connected == 0u || client->kexinit_exchanged == 0u ||
       client->key_exchange_complete == 0u || client->channel_open == 0u) {
        SSH_DEBUG("exec: bad state (client=%p command=%p connected=%u kexinit=%u key_complete=%u channel_open=%u)",
                  (void *)client,
                  (const void *)command,
                  (unsigned)(client != NULL ? client->connected : 0u),
                  (unsigned)(client != NULL ? client->kexinit_exchanged : 0u),
                  (unsigned)(client != NULL ? client->key_exchange_complete : 0u),
                  (unsigned)(client != NULL ? client->channel_open : 0u));
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(strlen(command) > (size_t)NETNOX_SSH_MAX_COMMAND_LEN) {
        SSH_DEBUG("exec: command too long (len=%u max=%u)",
                  (unsigned)strlen(command),
                  (unsigned)NETNOX_SSH_MAX_COMMAND_LEN);
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_REQUEST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_CHANNEL_REQ_EXEC, (uint32_t)strlen(NETNOX_SSH_CHANNEL_REQ_EXEC)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)command, (uint32_t)strlen(command)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_send_packet(client, payload, payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("exec: send CHANNEL_REQUEST(exec) failed");
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_CHANNEL_SUCCESS,
                                   NETNOX_SSH_MSG_CHANNEL_FAILURE,
                                   rsp,
                                   (uint32_t)sizeof(rsp),
                                   &rsp_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("exec: wait_for_message CHANNEL_SUCCESS/FAILURE failed");
        return NETNOX_RETURN_FAILED;
    }
    if(rsp_len == 0u || rsp[0] != NETNOX_SSH_MSG_CHANNEL_SUCCESS) {
        SSH_DEBUG("exec: request rejected (rsp_len=%u type=%u)",
                  (unsigned)rsp_len,
                  (unsigned)(rsp_len > 0u ? rsp[0] : 0xFFu));
        return NETNOX_RETURN_FAILED;
    }
    SSH_DEBUG("exec: CHANNEL_REQUEST(exec) accepted");
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_request_shell_ex(netnox_ssh_client_t * client,
                                                   uint8_t request_pty)
{
    uint8_t payload[512];
    uint32_t payload_len = 0u;
    uint8_t rsp[256];
    uint32_t rsp_len = 0u;

    if(client == NULL || client->connected == 0u || client->kexinit_exchanged == 0u ||
       client->key_exchange_complete == 0u || client->channel_open == 0u) {
        SSH_DEBUG("request_shell: bad state (client=%p connected=%u kexinit=%u key_complete=%u channel_open=%u)",
                  (void *)client,
                  (unsigned)(client != NULL ? client->connected : 0u),
                  (unsigned)(client != NULL ? client->kexinit_exchanged : 0u),
                  (unsigned)(client != NULL ? client->key_exchange_complete : 0u),
                  (unsigned)(client != NULL ? client->channel_open : 0u));
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(request_pty != 0u) {
        /* Ask server for a PTY so shell behaves interactively (prompts/line editing). */
        payload_len = 0u;
        if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_REQUEST) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                            (const uint8_t *)"pty-req",
                                            (uint32_t)strlen("pty-req")) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), 1u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                            (const uint8_t *)"xterm-256color",
                                            (uint32_t)strlen("xterm-256color")) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), 80u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), 24u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), 0u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), 0u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload), NULL, 0u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_send_packet(client, payload, payload_len) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("request_shell: send CHANNEL_REQUEST(pty-req) failed");
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_wait_for_message(client,
                                       NETNOX_SSH_MSG_CHANNEL_SUCCESS,
                                       NETNOX_SSH_MSG_CHANNEL_FAILURE,
                                       rsp,
                                       (uint32_t)sizeof(rsp),
                                       &rsp_len) != NETNOX_RETURN_SUCCESS) {
            SSH_DEBUG("request_shell: wait_for_message pty-req success/failure failed");
            return NETNOX_RETURN_FAILED;
        }
        if(rsp_len == 0u || rsp[0] != NETNOX_SSH_MSG_CHANNEL_SUCCESS) {
            SSH_DEBUG("request_shell: pty-req rejected (rsp_len=%u type=%u)",
                      (unsigned)rsp_len,
                      (unsigned)(rsp_len > 0u ? rsp[0] : 0xFFu));
            return NETNOX_RETURN_FAILED;
        }
        SSH_DEBUG("request_shell: CHANNEL_REQUEST(pty-req) accepted");
    } else {
        SSH_DEBUG("request_shell: PTY request disabled by caller");
    }

    payload_len = 0u;
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_REQUEST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)NETNOX_SSH_CHANNEL_REQ_SHELL,
                                        (uint32_t)strlen(NETNOX_SSH_CHANNEL_REQ_SHELL)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_send_packet(client, payload, payload_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("request_shell: send CHANNEL_REQUEST(shell) failed");
        return NETNOX_RETURN_FAILED;
    }

    if(netnox_ssh_wait_for_message(client,
                                   NETNOX_SSH_MSG_CHANNEL_SUCCESS,
                                   NETNOX_SSH_MSG_CHANNEL_FAILURE,
                                   rsp,
                                   (uint32_t)sizeof(rsp),
                                   &rsp_len) != NETNOX_RETURN_SUCCESS) {
        SSH_DEBUG("request_shell: wait_for_message CHANNEL_SUCCESS/FAILURE failed");
        return NETNOX_RETURN_FAILED;
    }

    if(rsp_len == 0u || rsp[0] != NETNOX_SSH_MSG_CHANNEL_SUCCESS) {
        SSH_DEBUG("request_shell: request rejected (rsp_len=%u type=%u)",
                  (unsigned)rsp_len,
                  (unsigned)(rsp_len > 0u ? rsp[0] : 0xFFu));
        return NETNOX_RETURN_FAILED;
    }
    SSH_DEBUG("request_shell: CHANNEL_REQUEST(shell) accepted");
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_request_shell(netnox_ssh_client_t * client)
{
    return netnox_ssh_client_request_shell_ex(client, 1u);
}

netnox_return_t netnox_ssh_client_send_data(netnox_ssh_client_t * client,
                                            const uint8_t * data,
                                            uint32_t len)
{
    if(client == NULL || data == NULL || len == 0u || len > NETNOX_SSH_MAX_DATA_LEN) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    uint8_t payload[4u + 1u + 4u + 4u + NETNOX_SSH_MAX_DATA_LEN];
    uint32_t payload_len = 0u;
    uint32_t chunk_len = len;

    if(client->connected == 0u || client->channel_open == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->remote_max_packet_size != 0u && chunk_len > client->remote_max_packet_size) {
        chunk_len = client->remote_max_packet_size;
    }
    if(chunk_len > NETNOX_SSH_MAX_DATA_LEN) {
        chunk_len = NETNOX_SSH_MAX_DATA_LEN;
    }

    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_DATA) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload), data, chunk_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }

    return netnox_ssh_send_packet(client, payload, payload_len);
}

netnox_return_t netnox_ssh_client_send_keepalive(netnox_ssh_client_t * client)
{
    uint8_t payload[1u + 4u];
    uint32_t payload_len = 0u;

    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->connected == 0u || client->key_exchange_complete == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_IGNORE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), 0u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    SSH_DEBUG3("keepalive: sending SSH_MSG_IGNORE");
    return netnox_ssh_send_packet(client, payload, payload_len);
}

netnox_return_t netnox_ssh_client_rekey(netnox_ssh_client_t * client)
{
    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->connected == 0u || client->key_exchange_complete == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    SSH_DEBUG("rekey: initiating key re-exchange");
    return netnox_ssh_exchange_kexinit(client);
}

netnox_return_t netnox_ssh_client_recv_data(netnox_ssh_client_t * client,
                                            uint8_t * data,
                                            uint32_t * len)
{
    uint8_t payload[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t payload_len = 0u;
    uint32_t offset = 1u;
    uint32_t recipient_channel = 0u;
    uint32_t data_type_code = 0u;
    uint8_t want_reply = 0u;
    const uint8_t * str_data = NULL;
    uint32_t str_len = 0u;
    const uint8_t * req_type = NULL;
    uint32_t req_type_len = 0u;
    uint32_t exit_status = 0u;
    uint32_t copy_len = 0u;

    if(client == NULL || data == NULL || len == NULL || *len == 0u || *len > NETNOX_SSH_MAX_DATA_LEN) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(client->connected == 0u || client->channel_open == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    for(;;) {
        if(netnox_ssh_recv_packet(client, payload, (uint32_t)sizeof(payload), &payload_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(payload_len == 0u) {
            continue;
        }
        if(payload[0] == NETNOX_SSH_MSG_KEXINIT) {
            SSH_DEBUG("recv_data: handling server-initiated KEXINIT");
            if(netnox_ssh_handle_server_kexinit(client, payload, payload_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            continue;
        }

        if(payload[0] == NETNOX_SSH_MSG_CHANNEL_DATA) {
            offset = 1u;
            if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &recipient_channel) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(recipient_channel != client->local_channel_id) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &str_data, &str_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            copy_len = (*len < str_len) ? *len : str_len;
            memcpy(data, str_data, copy_len);
            *len = copy_len;
            return NETNOX_RETURN_SUCCESS;
        }

        if(payload[0] == NETNOX_SSH_MSG_CHANNEL_EXTENDED_DATA) {
            offset = 1u;
            if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &recipient_channel) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(recipient_channel != client->local_channel_id) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &data_type_code) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &str_data, &str_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            copy_len = (*len < str_len) ? *len : str_len;
            memcpy(data, str_data, copy_len);
            *len = copy_len;
            SSH_DEBUG("recv_data: CHANNEL_EXTENDED_DATA type=%u len=%u",
                      (unsigned)data_type_code,
                      (unsigned)copy_len);
            return NETNOX_RETURN_SUCCESS;
        }

        if(payload[0] == NETNOX_SSH_MSG_CHANNEL_REQUEST) {
            offset = 1u;
            if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &recipient_channel) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(recipient_channel != client->local_channel_id) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &req_type, &req_type_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(offset >= payload_len) {
                return NETNOX_RETURN_FAILED;
            }
            want_reply = payload[offset++];
            (void)want_reply;
            if(req_type_len == (uint32_t)strlen("exit-status") &&
               memcmp(req_type, "exit-status", req_type_len) == 0) {
                if(netnox_ssh_payload_read_u32(payload, payload_len, &offset, &exit_status) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
                client->remote_exit_status = exit_status;
                client->remote_exit_status_valid = 1u;
                SSH_DEBUG("recv_data: captured remote exit-status=%u", (unsigned)exit_status);
            }
            continue;
        }

        if(payload[0] == NETNOX_SSH_MSG_CHANNEL_EOF) {
            /* Keep channel open state until CLOSE; EOF means no more remote payload data. */
            *len = 0u;
            return NETNOX_RETURN_SUCCESS;
        }

        if(payload[0] == NETNOX_SSH_MSG_CHANNEL_CLOSE) {
            client->channel_open = 0u;
            *len = 0u;
            return NETNOX_RETURN_SUCCESS;
        }
    }
}

netnox_return_t netnox_ssh_client_get_remote_exit_status(const netnox_ssh_client_t * client,
                                                         uint32_t * out_status)
{
    if(client == NULL || out_status == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(client->remote_exit_status_valid == 0u) {
        return NETNOX_RETURN_FAILED;
    }
    *out_status = client->remote_exit_status;
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_client_close(netnox_ssh_client_t * client)
{
    if(client == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    client->connected = 0u;
    client->kexinit_exchanged = 0u;
    client->key_exchange_complete = 0u;
    client->pending_newkeys_len = 0u;
    client->userauth_service_ready = 0u;
    client->authenticated = 0u;
    client->channel_open = 0u;
    client->local_channel_id = 0u;
    client->remote_channel_id = 0u;
    client->local_window_size = 0u;
    client->remote_window_size = 0u;
    client->remote_max_packet_size = 0u;
    client->server_host_key_blob_len = 0u;
    client->server_host_key_ready = 0u;
    memset(client->ed25519_private_key, 0, sizeof(client->ed25519_private_key));
    memset(client->ed25519_public_key, 0, sizeof(client->ed25519_public_key));
    client->has_ed25519_key = 0u;
    client->remote_exit_status_valid = 0u;
    client->remote_exit_status = 0u;
    client->server_ident[0] = '\0';
    return NETNOX_RETURN_SUCCESS;
}
