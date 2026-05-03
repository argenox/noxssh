/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* @file noxssh_server.c
* @brief SSH-2 server: curve25519-sha256, ssh-ed25519, aes128-ctr, hmac-sha2-256.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
/* Windows: one-shot exec uses _popen only. */
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char ** environ;
#endif

#include "noxssh_server.h"
#include "../noxtls/noxtls-lib/pkc/x25519/noxtls_x25519.h"
#include "../noxtls/noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#include "../noxtls/noxtls-lib/mdigest/noxtls_sha.h"
#include "../noxtls/noxtls-lib/encryption/aes/noxtls_aes.h"
#include "../noxtls/noxtls-lib/mdigest/noxtls_hash.h"

#define NETNOX_SSH_CHAR_CR ((char)'\r')
#define NETNOX_SSH_CHAR_LF ((char)'\n')
#define NETNOX_SSH_MIN_PADDING_LEN (4u)
#define NETNOX_SSH_PACKET_BLOCK_SIZE (8u)
#define NETNOX_SSH_KEXINIT_COOKIE_LEN (16u)
#define NETNOX_SSH_KEXINIT_PAYLOAD_MAX_LEN (1024u)
#define NETNOX_SSH_AES_BLOCK_LEN (16u)
#define NETNOX_SSH_MAC_LEN (32u)

static uint8_t g_srv_prng_seeded;

static int netnox_ssh_srv_debug(void)
{
    const char * env = getenv("NETNOX_SSH_DEBUG");
    if(env == NULL || env[0] == '\0') {
        return 0;
    }
    if(env[0] >= '1' && env[0] <= '3' && env[1] == '\0') {
        return (int)(env[0] - '0');
    }
    {
        int level = atoi(env);
        if(level < 0) {
            level = 0;
        } else if(level > 3) {
            level = 3;
        } else if(level == 0) {
            level = 1;
        }
        return level;
    }
}
#define SRVDBG(fmt, ...) \
    do { if(netnox_ssh_srv_debug() >= 1) (void)fprintf(stderr, "noxsshd: " fmt "\n", ##__VA_ARGS__); } while(0)

static void netnox_ssh_write_u32_be(uint8_t * out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xFFu);
    out[1] = (uint8_t)((value >> 16) & 0xFFu);
    out[2] = (uint8_t)((value >> 8) & 0xFFu);
    out[3] = (uint8_t)(value & 0xFFu);
}

static uint32_t netnox_ssh_read_u32_be(const uint8_t * in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static void netnox_ssh_fill_random(uint8_t * out, uint32_t len)
{
    uint32_t i;
    if(out == NULL || len == 0u) {
        return;
    }
    if(g_srv_prng_seeded == 0u) {
        srand((unsigned int)time(NULL));
        g_srv_prng_seeded = 1u;
    }
    for(i = 0u; i < len; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
}

static netnox_return_t netnox_ssh_copy_string(char * dst, uint16_t dst_len, const char * src)
{
    size_t src_len;
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
    uint32_t i;

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

static void netnox_ssh_ctr_increment_blocks(uint8_t * counter_16, uint32_t n_blocks)
{
    int i;
    uint64_t carry = (uint64_t)n_blocks;
    for(i = 15; i >= 0 && carry > 0u; i--) {
        carry += (uint64_t)counter_16[i];
        counter_16[i] = (uint8_t)(carry & 0xFFu);
        carry >>= 8;
    }
}

static netnox_return_t netnox_ssh_send_all(netnox_ssh_server_t * s, const uint8_t * data, uint32_t len)
{
    uint32_t sent_total = 0u;
    if(s == NULL || data == NULL || s->send_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    while(sent_total < len) {
        int32_t sent = s->send_cb(s->io_user_data, data + sent_total, len - sent_total);
        if(sent <= 0) {
            return NETNOX_RETURN_FAILED;
        }
        sent_total += (uint32_t)sent;
    }
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t netnox_ssh_recv_exact(netnox_ssh_server_t * s, uint8_t * data, uint32_t len)
{
    uint32_t recv_total = 0u;
    if(s == NULL || data == NULL || s->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    while(recv_total < len) {
        int32_t got = s->recv_cb(s->io_user_data, data + recv_total, len - recv_total);
        if(got <= 0) {
            return NETNOX_RETURN_FAILED;
        }
        recv_total += (uint32_t)got;
    }
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t netnox_ssh_recv_line(netnox_ssh_server_t * s, char * out, uint16_t out_len)
{
    uint16_t used = 0u;
    if(s == NULL || out == NULL || out_len == 0u || s->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    while(used < (uint16_t)(out_len - 1u)) {
        int32_t rc;
        uint8_t ch = 0u;
        rc = s->recv_cb(s->io_user_data, &ch, 1u);
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
    if(used == (uint16_t)(out_len - 1u)) {
        uint8_t ch = 0u;
        while(1) {
            int32_t rc = s->recv_cb(s->io_user_data, &ch, 1u);
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

static int netnox_ssh_is_ident_line(const char * line)
{
    if(line == NULL) {
        return 0;
    }
    return (strncmp(line, "SSH-", 4u) == 0) ? 1 : 0;
}

static netnox_return_t netnox_ssh_payload_append_namelist(uint8_t * payload,
                                                          uint32_t * payload_len,
                                                          uint32_t payload_max,
                                                          const char * list)
{
    uint32_t list_len;
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

static netnox_return_t netnox_ssh_payload_read_string_view(const uint8_t * payload,
                                                           uint32_t payload_len,
                                                           uint32_t * offset,
                                                           const uint8_t ** out_data,
                                                           uint32_t * out_len)
{
    uint32_t str_len;
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

static int netnox_ssh_namelist_contains(const uint8_t * list, uint32_t list_len, const char * token)
{
    uint32_t start = 0u;
    uint32_t token_len;
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

static netnox_return_t netnox_ssh_validate_client_kexinit(const uint8_t * payload, uint32_t payload_len)
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
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_HOST_KEY_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_CIPHER_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_CIPHER_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_MAC_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_MAC_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_COMPRESSION_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_namelist_contains(field, field_len, NETNOX_SSH_REQUIRED_COMPRESSION_ALG) == 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(payload, payload_len, &offset, &field, &field_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return NETNOX_RETURN_SUCCESS;
}

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

static netnox_return_t netnox_ssh_buf_append_mpint_be(uint8_t * out,
                                                      uint32_t * out_len,
                                                      uint32_t out_max,
                                                      const uint8_t * in,
                                                      uint32_t in_len)
{
    uint32_t first = 0u;
    uint32_t value_len;
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

static netnox_return_t srv_compute_exchange_hash(netnox_ssh_server_t * s,
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
    noxtls_return_t noxrc;

    if(s == NULL || host_key_blob == NULL || client_pub == NULL || server_pub == NULL ||
       shared_secret_raw == NULL || out_hash == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        (const uint8_t *)s->client_ident,
                                        (uint32_t)strlen(s->client_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        (const uint8_t *)s->server_ident,
                                        (uint32_t)strlen(s->server_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        s->kexinit_client_payload,
                                        s->kexinit_client_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        s->kexinit_server_payload,
                                        s->kexinit_server_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        host_key_blob, host_key_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        client_pub, client_pub_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                        server_pub, server_pub_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append_mpint_be(h_input, &h_input_len, (uint32_t)sizeof(h_input),
                                      shared_secret_raw, shared_secret_raw_len) != NETNOX_RETURN_SUCCESS) {
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

static netnox_return_t srv_derive_key_block(netnox_ssh_server_t * s,
                                            uint8_t selector,
                                            uint8_t * out,
                                            uint32_t out_len)
{
    uint8_t seed[1024];
    uint32_t seed_len = 0u;
    uint8_t digest[32];
    noxtls_sha_ctx_t sha_ctx;
    noxtls_return_t noxrc;
    uint32_t produced = 0u;
    uint32_t take;
    int use_mpint = 1;
    uint8_t k_enc[4u + 33u];
    uint32_t k_enc_len = 0u;

    if(s == NULL || out == NULL || out_len == 0u || s->session_id_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    {
        const char * env = getenv("NETNOX_SSH_KEY_DERIV_MPINT");
        if(env != NULL && env[0] == '0' && env[1] == '\0') {
            use_mpint = 0;
        }
    }
    if(use_mpint) {
        if(netnox_ssh_buf_append_mpint_be(k_enc, &k_enc_len, (uint32_t)sizeof(k_enc),
                                          s->shared_secret_raw, (uint32_t)sizeof(s->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), k_enc, k_enc_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
    } else {
        if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed),
                                 s->shared_secret_raw, (uint32_t)sizeof(s->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), s->session_id, s->session_id_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), &selector, 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_buf_append(seed, &seed_len, (uint32_t)sizeof(seed), s->session_id, s->session_id_len) != NETNOX_RETURN_SUCCESS) {
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
                                              s->shared_secret_raw, (uint32_t)sizeof(s->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in), k_enc, k_enc_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
        } else {
            if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in),
                                    s->shared_secret_raw, (uint32_t)sizeof(s->shared_secret_raw)) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
        }
        if(netnox_ssh_buf_append(cont_in, &cont_len, (uint32_t)sizeof(cont_in), s->session_id, s->session_id_len) != NETNOX_RETURN_SUCCESS) {
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

static netnox_return_t srv_derive_transport_keys(netnox_ssh_server_t * s)
{
    if(s == NULL || s->session_id_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(srv_derive_key_block(s, (uint8_t)'A', s->c2s_iv, (uint32_t)sizeof(s->c2s_iv)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_derive_key_block(s, (uint8_t)'B', s->s2c_iv, (uint32_t)sizeof(s->s2c_iv)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_derive_key_block(s, (uint8_t)'C', s->c2s_key, (uint32_t)sizeof(s->c2s_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_derive_key_block(s, (uint8_t)'D', s->s2c_key, (uint32_t)sizeof(s->s2c_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_derive_key_block(s, (uint8_t)'E', s->c2s_mac_key, (uint32_t)sizeof(s->c2s_mac_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_derive_key_block(s, (uint8_t)'F', s->s2c_mac_key, (uint32_t)sizeof(s->s2c_mac_key)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(s->c2s_counter, s->c2s_iv, NETNOX_SSH_AES_BLOCK_LEN);
    memcpy(s->s2c_counter, s->s2c_iv, NETNOX_SSH_AES_BLOCK_LEN);
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_send_packet(netnox_ssh_server_t * s,
                                       const uint8_t * payload,
                                       uint32_t payload_len);
static netnox_return_t srv_recv_packet(netnox_ssh_server_t * s,
                                       uint8_t * payload_out,
                                       uint32_t payload_max,
                                       uint32_t * payload_len_out);

static netnox_return_t srv_build_host_key_blob(netnox_ssh_server_t * s,
                                               uint8_t * out,
                                               uint32_t out_max,
                                               uint32_t * out_len)
{
    static const char alg[] = "ssh-ed25519";
    uint32_t len = 0u;
    if(s == NULL || out == NULL || out_len == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    *out_len = 0u;
    if(netnox_ssh_payload_append_string(out, &len, out_max,
                                        (const uint8_t *)alg, (uint32_t)strlen(alg)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(out, &len, out_max, s->host_ed25519_pk, 32u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    *out_len = len;
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_build_kexinit_payload(uint8_t * payload,
                                                 uint32_t * payload_len,
                                                 uint32_t payload_max)
{
    uint32_t i;
    netnox_return_t rc;
    if(payload == NULL || payload_len == NULL || payload_max < (1u + NETNOX_SSH_KEXINIT_COOKIE_LEN)) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    payload[0] = NETNOX_SSH_MSG_KEXINIT;
    *payload_len = 1u;
    netnox_ssh_fill_random(&payload[*payload_len], NETNOX_SSH_KEXINIT_COOKIE_LEN);
    *payload_len += NETNOX_SSH_KEXINIT_COOKIE_LEN;
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_KEX_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_HOST_KEY_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_CIPHER_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_CIPHER_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_MAC_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_MAC_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_COMPRESSION_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, NETNOX_SSH_COMPRESSION_ALG_LIST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, "");
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    rc = netnox_ssh_payload_append_namelist(payload, payload_len, payload_max, "");
    if(rc != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if((*payload_len + 1u + 4u) > payload_max) {
        return NETNOX_RETURN_FAILED;
    }
    payload[*payload_len] = 0u;
    *payload_len += 1u;
    netnox_ssh_write_u32_be(&payload[*payload_len], 0u);
    *payload_len += 4u;
    for(i = 0u; i < *payload_len; i++) {
        (void)payload[i];
    }
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_send_packet(netnox_ssh_server_t * s,
                                       const uint8_t * payload,
                                       uint32_t payload_len)
{
    uint32_t padding_len = NETNOX_SSH_MIN_PADDING_LEN;
    uint32_t packet_len;
    uint32_t plain_len;
    uint32_t n_blocks;
    uint32_t block_size;
    uint8_t plain[4u + NETNOX_SSH_MAX_PACKET_LEN];
    uint8_t enc[4u + NETNOX_SSH_MAX_PACKET_LEN];
    uint8_t mac_buf[NETNOX_SSH_MAC_LEN];
    uint8_t seq_be[4];
    netnox_return_t send_rc;
    noxtls_return_t aes_rc;

    if(s == NULL || payload == NULL || payload_len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    block_size = (s->key_exchange_complete != 0u) ? NETNOX_SSH_AES_BLOCK_LEN : NETNOX_SSH_PACKET_BLOCK_SIZE;
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

    if(s->key_exchange_complete != 0u) {
        uint8_t mac_input[4u + 4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint32_t enc_mac_len = plain_len + NETNOX_SSH_MAC_LEN;
        netnox_ssh_write_u32_be(seq_be, s->send_seq);
        memcpy(mac_input, seq_be, 4u);
        memcpy(mac_input + 4u, plain, plain_len);
        if(netnox_ssh_hmac_sha256(s->s2c_mac_key, (uint32_t)sizeof(s->s2c_mac_key),
                                  mac_input, 4u + plain_len, mac_buf) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        aes_rc = aes_encrypt_ctr(s->s2c_key, plain, plain_len, s->s2c_counter, enc, AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        n_blocks = (plain_len + NETNOX_SSH_AES_BLOCK_LEN - 1u) / NETNOX_SSH_AES_BLOCK_LEN;
        netnox_ssh_ctr_increment_blocks(s->s2c_counter, n_blocks);
        {
            uint8_t combined[128];
            uint32_t total = s->pending_newkeys_len + enc_mac_len;
            if(total > 0u && total <= (uint32_t)sizeof(combined)) {
                uint32_t off = 0u;
                if(s->pending_newkeys_len > 0u) {
                    memcpy(combined, s->pending_newkeys, s->pending_newkeys_len);
                    off = s->pending_newkeys_len;
                    s->pending_newkeys_len = 0u;
                }
                memcpy(combined + off, enc, plain_len);
                memcpy(combined + off + plain_len, mac_buf, NETNOX_SSH_MAC_LEN);
                if(netnox_ssh_send_all(s, combined, total) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
            } else {
                if(s->pending_newkeys_len > 0u) {
                    if(netnox_ssh_send_all(s, s->pending_newkeys, s->pending_newkeys_len) != NETNOX_RETURN_SUCCESS) {
                        return NETNOX_RETURN_FAILED;
                    }
                    s->pending_newkeys_len = 0u;
                }
                memcpy(combined, enc, plain_len);
                memcpy(combined + plain_len, mac_buf, NETNOX_SSH_MAC_LEN);
                if(netnox_ssh_send_all(s, combined, enc_mac_len) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
            }
        }
        s->send_seq++;
        s->encrypted_bytes_sent += (uint64_t)enc_mac_len;
        return NETNOX_RETURN_SUCCESS;
    }
    if(payload_len == 1u && payload[0] == NETNOX_SSH_MSG_NEWKEYS) {
        send_rc = netnox_ssh_send_all(s, plain, plain_len);
        if(send_rc == NETNOX_RETURN_SUCCESS) {
            s->send_seq++;
        }
        return send_rc;
    }
    send_rc = netnox_ssh_send_all(s, plain, plain_len);
    if(send_rc == NETNOX_RETURN_SUCCESS) {
        s->send_seq++;
    }
    return send_rc;
}

static netnox_return_t srv_recv_packet(netnox_ssh_server_t * s,
                                       uint8_t * payload_out,
                                       uint32_t payload_max,
                                       uint32_t * payload_len_out)
{
    uint8_t len_buf[4];
    uint8_t packet[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t packet_len;
    uint32_t payload_len;
    uint8_t padding_len;

    if(s == NULL || payload_out == NULL || payload_len_out == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }

    if(s->key_exchange_complete != 0u) {
        uint8_t enc[4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint8_t plain[4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint8_t mac_buf[NETNOX_SSH_MAC_LEN];
        uint8_t mac_input[4u + 4u + NETNOX_SSH_MAX_PACKET_LEN];
        uint8_t computed_mac[NETNOX_SSH_MAC_LEN];
        uint32_t plain_len;
        uint32_t n_blocks;
        noxtls_return_t aes_rc;

        if(netnox_ssh_recv_exact(s, enc, NETNOX_SSH_AES_BLOCK_LEN) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        aes_rc = aes_encrypt_ctr(s->c2s_key, enc, NETNOX_SSH_AES_BLOCK_LEN, s->c2s_counter, plain, AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_ctr_increment_blocks(s->c2s_counter, 1u);
        packet_len = netnox_ssh_read_u32_be(&plain[0]);
        if(packet_len < (1u + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN) {
            return NETNOX_RETURN_FAILED;
        }
        plain_len = 4u + packet_len;
        if(netnox_ssh_recv_exact(s, &enc[NETNOX_SSH_AES_BLOCK_LEN], plain_len - NETNOX_SSH_AES_BLOCK_LEN) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        aes_rc = aes_encrypt_ctr(s->c2s_key, &enc[NETNOX_SSH_AES_BLOCK_LEN], plain_len - NETNOX_SSH_AES_BLOCK_LEN,
                                 s->c2s_counter, &plain[NETNOX_SSH_AES_BLOCK_LEN], AES_128_BIT);
        if(aes_rc != NOXTLS_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        n_blocks = (plain_len + NETNOX_SSH_AES_BLOCK_LEN - 1u) / NETNOX_SSH_AES_BLOCK_LEN;
        netnox_ssh_ctr_increment_blocks(s->c2s_counter, n_blocks - 1u);
        if(netnox_ssh_recv_exact(s, mac_buf, NETNOX_SSH_MAC_LEN) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        netnox_ssh_write_u32_be(mac_input, s->recv_seq);
        memcpy(mac_input + 4u, plain, plain_len);
        if(netnox_ssh_hmac_sha256(s->c2s_mac_key, (uint32_t)sizeof(s->c2s_mac_key),
                                  mac_input, 4u + plain_len, computed_mac) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(memcmp(computed_mac, mac_buf, NETNOX_SSH_MAC_LEN) != 0) {
            return NETNOX_RETURN_FAILED;
        }
        s->recv_seq++;
        s->encrypted_bytes_recv += (uint64_t)(plain_len + NETNOX_SSH_MAC_LEN);
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

    if(netnox_ssh_recv_exact(s, len_buf, sizeof(len_buf)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    packet_len = netnox_ssh_read_u32_be(len_buf);
    if(packet_len < (1u + NETNOX_SSH_MIN_PADDING_LEN) || packet_len > NETNOX_SSH_MAX_PACKET_LEN) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_recv_exact(s, packet, packet_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    padding_len = packet[0];
    if(padding_len < NETNOX_SSH_MIN_PADDING_LEN || (uint32_t)padding_len >= packet_len) {
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
    s->recv_seq++;
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_exchange_kexinit(netnox_ssh_server_t * s)
{
    uint8_t rx_payload[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t rx_payload_len = 0u;
    uint8_t tx_payload[NETNOX_SSH_KEXINIT_PAYLOAD_MAX_LEN];
    uint32_t tx_payload_len = 0u;

    if(s == NULL || s->connected == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(srv_recv_packet(s, rx_payload, (uint32_t)sizeof(rx_payload), &rx_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(rx_payload_len == 0u || rx_payload[0] != NETNOX_SSH_MSG_KEXINIT) {
        return NETNOX_RETURN_FAILED;
    }
    if(rx_payload_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(s->kexinit_client_payload, rx_payload, rx_payload_len);
    s->kexinit_client_payload_len = rx_payload_len;
    if(netnox_ssh_validate_client_kexinit(rx_payload, rx_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_build_kexinit_payload(tx_payload, &tx_payload_len, (uint32_t)sizeof(tx_payload)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(tx_payload_len > NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(s->kexinit_server_payload, tx_payload, tx_payload_len);
    s->kexinit_server_payload_len = tx_payload_len;
    if(srv_send_packet(s, tx_payload, tx_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    s->kexinit_exchanged = 1u;
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_perform_curve25519_kex(netnox_ssh_server_t * s)
{
    uint8_t priv_s[32];
    uint8_t pub_s[32];
    uint8_t shared_raw[32];
    uint8_t init_payload[2048];
    uint32_t init_payload_len = 0u;
    uint8_t host_blob[256];
    uint32_t host_blob_len = 0u;
    uint8_t H[32];
    uint8_t sig64[64];
    uint8_t sig_wire[128];
    uint32_t sig_wire_len = 0u;
    uint8_t reply[2048];
    uint32_t reply_len = 0u;
    const uint8_t * pub_c = NULL;
    uint32_t pub_c_len = 0u;
    uint32_t off = 1u;
    uint8_t newkeys_payload[1];

    if(s == NULL || s->kexinit_exchanged == 0u || s->host_key_ready == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(srv_recv_packet(s, init_payload, (uint32_t)sizeof(init_payload), &init_payload_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(init_payload_len == 0u || init_payload[0] != NETNOX_SSH_MSG_KEX_ECDH_INIT) {
        return NETNOX_RETURN_FAILED;
    }
    off = 1u;
    if(netnox_ssh_payload_read_string_view(init_payload, init_payload_len, &off, &pub_c, &pub_c_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(pub_c_len != 32u) {
        return NETNOX_RETURN_FAILED;
    }
    if(noxtls_x25519_generate_key(priv_s, pub_s) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(noxtls_x25519_shared_secret(priv_s, pub_c, shared_raw) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_build_host_key_blob(s, host_blob, (uint32_t)sizeof(host_blob), &host_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_compute_exchange_hash(s, host_blob, host_blob_len,
                                 pub_c, pub_c_len, pub_s, 32u,
                                 shared_raw, (uint32_t)sizeof(shared_raw), H) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    memcpy(s->session_id, H, 32u);
    s->session_id_len = 32u;
    memcpy(s->shared_secret_raw, shared_raw, sizeof(shared_raw));
    if(noxtls_ed25519_sign(s->host_ed25519_sk, H, 32u, sig64) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    {
        static const char sig_alg[] = "ssh-ed25519";
        sig_wire_len = 0u;
        if(netnox_ssh_payload_append_string(sig_wire, &sig_wire_len, (uint32_t)sizeof(sig_wire),
                                            (const uint8_t *)sig_alg, (uint32_t)strlen(sig_alg)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_payload_append_string(sig_wire, &sig_wire_len, (uint32_t)sizeof(sig_wire),
                                            sig64, 64u) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
    }
    reply_len = 0u;
    if(netnox_ssh_payload_append_u8(reply, &reply_len, (uint32_t)sizeof(reply), NETNOX_SSH_MSG_KEX_ECDH_REPLY) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(reply, &reply_len, (uint32_t)sizeof(reply), host_blob, host_blob_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(reply, &reply_len, (uint32_t)sizeof(reply), pub_s, 32u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(reply, &reply_len, (uint32_t)sizeof(reply), sig_wire, sig_wire_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_send_packet(s, reply, reply_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    newkeys_payload[0] = NETNOX_SSH_MSG_NEWKEYS;
    if(srv_send_packet(s, newkeys_payload, 1u) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    {
        uint8_t rx[64];
        uint32_t rx_len = 0u;
        if(srv_recv_packet(s, rx, (uint32_t)sizeof(rx), &rx_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(rx_len == 0u || rx[0] != NETNOX_SSH_MSG_NEWKEYS) {
            return NETNOX_RETURN_FAILED;
        }
    }
    if(srv_derive_transport_keys(s) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    s->key_exchange_complete = 1u;
    s->send_seq = 0u;
    s->recv_seq = 0u;
    return NETNOX_RETURN_SUCCESS;
}

static netnox_return_t srv_send_service_accept(netnox_ssh_server_t * s, const char * service)
{
    uint8_t payload[256];
    uint32_t payload_len = 0u;
    if(s == NULL || service == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_SERVICE_ACCEPT) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)service, (uint32_t)strlen(service)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_userauth_failure(netnox_ssh_server_t * s, int partial)
{
    uint8_t payload[256];
    uint32_t payload_len = 0u;
    const char * methods = "password,publickey";
    if(s == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_USERAUTH_FAILURE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload),
                                        (const uint8_t *)methods, (uint32_t)strlen(methods)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), (uint8_t)(partial ? 1u : 0u)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_userauth_success(netnox_ssh_server_t * s)
{
    uint8_t p[1] = { NETNOX_SSH_MSG_USERAUTH_SUCCESS };
    return srv_send_packet(s, p, 1u);
}

static netnox_return_t srv_send_global_request_failure(netnox_ssh_server_t * s)
{
    uint8_t p[1] = { NETNOX_SSH_MSG_REQUEST_FAILURE };
    return srv_send_packet(s, p, 1u);
}

static netnox_return_t srv_send_channel_open_confirmation(netnox_ssh_server_t * s,
                                                        uint32_t client_sender_channel)
{
    uint8_t payload[128];
    uint32_t payload_len = 0u;
    s->local_channel_id = 0u;
    s->remote_channel_id = client_sender_channel;
    s->local_window_size = NETNOX_SSH_CHANNEL_WINDOW_SIZE;
    /* remote_window_size / remote_max_packet_size set by caller from CHANNEL_OPEN */
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload),
                                    NETNOX_SSH_MSG_CHANNEL_OPEN_CONFIRMATION) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), client_sender_channel) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->local_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->local_window_size) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_channel_failure(netnox_ssh_server_t * s)
{
    uint8_t payload[64];
    uint32_t payload_len = 0u;
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_FAILURE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_channel_success(netnox_ssh_server_t * s)
{
    uint8_t payload[64];
    uint32_t payload_len = 0u;
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_SUCCESS) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_channel_data_chunk(netnox_ssh_server_t * s,
                                                   const uint8_t * data,
                                                   uint32_t len)
{
    uint8_t payload[4u + 1u + 4u + 4u + NETNOX_SSH_MAX_DATA_LEN];
    uint32_t payload_len = 0u;
    uint32_t max_chunk;
    if(s == NULL || data == NULL || len == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    max_chunk = NETNOX_SSH_MAX_DATA_LEN;
    if(s->remote_max_packet_size > 64u && max_chunk > s->remote_max_packet_size - 64u) {
        max_chunk = s->remote_max_packet_size - 64u;
    }
    if(len > max_chunk) {
        len = max_chunk;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_DATA) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_string(payload, &payload_len, (uint32_t)sizeof(payload), data, len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(s->remote_window_size < len) {
        return NETNOX_RETURN_FAILED;
    }
    s->remote_window_size -= len;
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_channel_eof(netnox_ssh_server_t * s)
{
    uint8_t payload[32];
    uint32_t payload_len = 0u;
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_EOF) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_send_channel_close(netnox_ssh_server_t * s)
{
    uint8_t payload[32];
    uint32_t payload_len = 0u;
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_CLOSE) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->remote_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return srv_send_packet(s, payload, payload_len);
}

static netnox_return_t srv_maybe_window_adjust(netnox_ssh_server_t * s)
{
    uint8_t payload[64];
    uint32_t payload_len = 0u;
    const uint32_t bump = 262144u;
    if(s->local_window_size > 65536u) {
        return NETNOX_RETURN_SUCCESS;
    }
    if(netnox_ssh_payload_append_u8(payload, &payload_len, (uint32_t)sizeof(payload), NETNOX_SSH_MSG_CHANNEL_WINDOW_ADJUST) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), s->local_channel_id) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_append_u32(payload, &payload_len, (uint32_t)sizeof(payload), bump) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    s->local_window_size += bump;
    return srv_send_packet(s, payload, payload_len);
}

#ifndef _WIN32
static netnox_return_t srv_run_exec_unix(netnox_ssh_server_t * s, const char * cmd)
{
    int fd[2];
    pid_t pid;
    ssize_t n;
    uint8_t buf[4096];

    if(pipe(fd) != 0) {
        return NETNOX_RETURN_FAILED;
    }
    pid = fork();
    if(pid == (pid_t)0) {
        char * argv[4];
        (void)close(fd[0]);
        if(dup2(fd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        if(dup2(fd[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        (void)close(fd[1]);
        argv[0] = (char *)"sh";
        argv[1] = (char *)"-c";
        argv[2] = (char *)cmd;
        argv[3] = NULL;
        (void)execve("/bin/sh", argv, environ);
        _exit(127);
    }
    if(pid < (pid_t)0) {
        (void)close(fd[0]);
        (void)close(fd[1]);
        return NETNOX_RETURN_FAILED;
    }
    (void)close(fd[1]);
    while((n = read(fd[0], buf, sizeof(buf))) > 0) {
        uint32_t rem = (uint32_t)n;
        uint32_t pos = 0u;
        while(rem > 0u) {
            uint32_t chunk = rem > 32000u ? 32000u : rem;
            if(srv_send_channel_data_chunk(s, buf + pos, chunk) != NETNOX_RETURN_SUCCESS) {
                (void)close(fd[0]);
                (void)waitpid(pid, NULL, 0);
                return NETNOX_RETURN_FAILED;
            }
            pos += chunk;
            rem -= chunk;
        }
    }
    (void)close(fd[0]);
    (void)waitpid(pid, NULL, 0);
    (void)srv_send_channel_eof(s);
    (void)srv_send_channel_close(s);
    s->channel_open = 0u;
    return NETNOX_RETURN_SUCCESS;
}
#else
static netnox_return_t srv_run_exec_win32(netnox_ssh_server_t * s, const char * cmd)
{
    char line[NETNOX_SSH_MAX_COMMAND_LEN + 32u];
    FILE * fp;
    uint8_t buf[4096];
    size_t n;

    if(strlen(cmd) + 16u >= sizeof(line)) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(snprintf(line, sizeof(line), "cmd /c \"%s\"", cmd) <= 0) {
        return NETNOX_RETURN_FAILED;
    }
    fp = _popen(line, "rb");
    if(fp == NULL) {
        return NETNOX_RETURN_FAILED;
    }
    while((n = fread(buf, 1u, sizeof(buf), fp)) > 0u) {
        uint32_t rem = (uint32_t)n;
        uint32_t pos = 0u;
        while(rem > 0u) {
            uint32_t chunk = rem > 32000u ? 32000u : rem;
            if(srv_send_channel_data_chunk(s, buf + pos, chunk) != NETNOX_RETURN_SUCCESS) {
                (void)_pclose(fp);
                return NETNOX_RETURN_FAILED;
            }
            pos += chunk;
            rem -= chunk;
        }
    }
    (void)_pclose(fp);
    (void)srv_send_channel_eof(s);
    (void)srv_send_channel_close(s);
    s->channel_open = 0u;
    return NETNOX_RETURN_SUCCESS;
}
#endif

static netnox_return_t srv_handle_userauth_request(netnox_ssh_server_t * s,
                                                   const uint8_t * p,
                                                   uint32_t plen)
{
    uint32_t off = 1u;
    const uint8_t * user = NULL;
    uint32_t user_len = 0u;
    const uint8_t * service = NULL;
    uint32_t service_len = 0u;
    const uint8_t * method = NULL;
    uint32_t method_len = 0u;
    if(plen < 2u || p[0] != NETNOX_SSH_MSG_USERAUTH_REQUEST) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(p, plen, &off, &user, &user_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(p, plen, &off, &service, &service_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_payload_read_string_view(p, plen, &off, &method, &method_len) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    (void)user;
    (void)user_len;
    if(service_len != strlen(NETNOX_SSH_SERVICE_CONNECTION) ||
       memcmp(service, NETNOX_SSH_SERVICE_CONNECTION, service_len) != 0) {
        return srv_send_userauth_failure(s, 0);
    }
    if(method_len == strlen(NETNOX_SSH_AUTH_METHOD_PASSWORD) &&
       memcmp(method, NETNOX_SSH_AUTH_METHOD_PASSWORD, method_len) == 0) {
        uint8_t change = 0u;
        const uint8_t * pw = NULL;
        uint32_t pw_len = 0u;
        if(off >= plen) {
            return NETNOX_RETURN_FAILED;
        }
        change = p[off++];
        (void)change;
        if(netnox_ssh_payload_read_string_view(p, plen, &off, &pw, &pw_len) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(s->allowed_password[0] == '\0') {
            return srv_send_userauth_failure(s, 0);
        }
        if(pw_len == strlen(s->allowed_password) && memcmp(pw, s->allowed_password, pw_len) == 0) {
            s->authenticated = 1u;
            return srv_send_userauth_success(s);
        }
        return srv_send_userauth_failure(s, 0);
    }
    if(method_len == strlen("publickey") && memcmp(method, "publickey", method_len) == 0) {
        /* Probe or verify: not implemented — RFC 4252 continuation. */
        return srv_send_userauth_failure(s, 1);
    }
    return srv_send_userauth_failure(s, 0);
}

static netnox_return_t srv_handshake_to_encrypted(netnox_ssh_server_t * s)
{
    uint8_t bi;
    char line[NETNOX_SSH_MAX_IDENT_LEN + 1u];
    char tx_ident[NETNOX_SSH_MAX_IDENT_LEN + 3u];

    if(s->host_key_ready == 0u) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    for(bi = 0u; bi < NETNOX_SSH_MAX_BANNER_LINES; bi++) {
        if(netnox_ssh_recv_line(s, line, (uint16_t)sizeof(line)) != NETNOX_RETURN_SUCCESS) {
            return NETNOX_RETURN_FAILED;
        }
        if(netnox_ssh_is_ident_line(line) != 0) {
            if(netnox_ssh_copy_string(s->client_ident, (uint16_t)sizeof(s->client_ident), line) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            break;
        }
    }
    if(s->client_ident[0] == '\0') {
        return NETNOX_RETURN_FAILED;
    }
    if(snprintf(tx_ident, sizeof(tx_ident), "%s\r\n", s->server_ident) <= 0) {
        return NETNOX_RETURN_FAILED;
    }
    if(netnox_ssh_send_all(s, (const uint8_t *)tx_ident, (uint32_t)strlen(tx_ident)) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    s->connected = 1u;
    if(srv_exchange_kexinit(s) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    if(srv_perform_curve25519_kex(s) != NETNOX_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_server_init(netnox_ssh_server_t * server)
{
    if(server == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    memset(server, 0, sizeof(*server));
    server->rekey_threshold_bytes = (uint64_t)256 * 1024u * 1024u;
    return netnox_ssh_copy_string(server->server_ident, (uint16_t)sizeof(server->server_ident), NETNOX_SSH_DEFAULT_SERVER_IDENT);
}

void netnox_ssh_server_set_io_callbacks(netnox_ssh_server_t * server,
                                        netnox_ssh_transport_send_t send_cb,
                                        netnox_ssh_transport_recv_t recv_cb,
                                        void * io_user_data)
{
    if(server == NULL) {
        return;
    }
    server->send_cb = send_cb;
    server->recv_cb = recv_cb;
    server->io_user_data = io_user_data;
}

netnox_return_t netnox_ssh_server_set_identification(netnox_ssh_server_t * server, const char * server_ident)
{
    if(server == NULL || server_ident == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    return netnox_ssh_copy_string(server->server_ident, (uint16_t)sizeof(server->server_ident), server_ident);
}

netnox_return_t netnox_ssh_server_set_host_ed25519_seed(netnox_ssh_server_t * server,
                                                       const uint8_t secret_seed[32])
{
    if(server == NULL || secret_seed == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    memcpy(server->host_ed25519_sk, secret_seed, 32u);
    if(noxtls_ed25519_public_key(server->host_ed25519_sk, server->host_ed25519_pk) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    server->host_key_ready = 1u;
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_server_generate_host_ed25519_key(netnox_ssh_server_t * server)
{
    if(server == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(noxtls_ed25519_generate_key(server->host_ed25519_sk, server->host_ed25519_pk) != NOXTLS_RETURN_SUCCESS) {
        return NETNOX_RETURN_FAILED;
    }
    server->host_key_ready = 1u;
    return NETNOX_RETURN_SUCCESS;
}

netnox_return_t netnox_ssh_server_set_allowed_password(netnox_ssh_server_t * server, const char * password)
{
    if(server == NULL || password == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    return netnox_ssh_copy_string(server->allowed_password, (uint16_t)sizeof(server->allowed_password), password);
}

void netnox_ssh_server_reset(netnox_ssh_server_t * server)
{
    if(server == NULL) {
        return;
    }
    memset(server->client_ident, 0, sizeof(server->client_ident));
    server->connected = 0u;
    server->kexinit_exchanged = 0u;
    server->userauth_service_ready = 0u;
    server->connection_service_ready = 0u;
    server->authenticated = 0u;
    server->channel_open = 0u;
    server->key_exchange_complete = 0u;
    server->send_seq = 0u;
    server->recv_seq = 0u;
    server->pending_newkeys_len = 0u;
    server->encrypted_bytes_sent = 0u;
    server->encrypted_bytes_recv = 0u;
}

netnox_return_t netnox_ssh_server_serve_one(netnox_ssh_server_t * s)
{
    uint8_t payload[NETNOX_SSH_MAX_PACKET_LEN];
    uint32_t payload_len = 0u;

    if(s == NULL || s->send_cb == NULL || s->recv_cb == NULL) {
        return NETNOX_RETURN_BAD_PARAM;
    }
    if(srv_handshake_to_encrypted(s) != NETNOX_RETURN_SUCCESS) {
        SRVDBG("handshake failed");
        return NETNOX_RETURN_FAILED;
    }

    for(;;) {
        if(srv_recv_packet(s, payload, (uint32_t)sizeof(payload), &payload_len) != NETNOX_RETURN_SUCCESS) {
            break;
        }
        if(payload_len == 0u) {
            continue;
        }
        if(s->rekey_threshold_bytes > 0u &&
           (s->encrypted_bytes_sent >= s->rekey_threshold_bytes ||
            s->encrypted_bytes_recv >= s->rekey_threshold_bytes)) {
            /* Full mid-session rekey not implemented; counters reserved for RFC 4253 §9. */
            SRVDBG("rekey threshold reached (not implemented)");
        }
        switch(payload[0]) {
        case NETNOX_SSH_MSG_DISCONNECT:
            return NETNOX_RETURN_SUCCESS;
        case NETNOX_SSH_MSG_IGNORE:
        case NETNOX_SSH_MSG_EXT_INFO:
            continue;
        case NETNOX_SSH_MSG_GLOBAL_REQUEST: {
            uint32_t off = 1u;
            const uint8_t * req = NULL;
            uint32_t req_len = 0u;
            uint8_t want = 0u;
            if(payload_len < 3u) {
                continue;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &req, &req_len) != NETNOX_RETURN_SUCCESS) {
                continue;
            }
            if(off >= payload_len) {
                continue;
            }
            want = payload[off];
            if(want != 0u) {
                (void)srv_send_global_request_failure(s);
            }
            continue;
        }
        case NETNOX_SSH_MSG_SERVICE_REQUEST: {
            uint32_t off = 1u;
            const uint8_t * svc = NULL;
            uint32_t svc_len = 0u;
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &svc, &svc_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(svc_len == strlen(NETNOX_SSH_SERVICE_USERAUTH) &&
               memcmp(svc, NETNOX_SSH_SERVICE_USERAUTH, svc_len) == 0) {
                s->userauth_service_ready = 1u;
                if(srv_send_service_accept(s, NETNOX_SSH_SERVICE_USERAUTH) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
                continue;
            }
            if(s->authenticated != 0u && svc_len == strlen(NETNOX_SSH_SERVICE_CONNECTION) &&
               memcmp(svc, NETNOX_SSH_SERVICE_CONNECTION, svc_len) == 0) {
                s->connection_service_ready = 1u;
                if(srv_send_service_accept(s, NETNOX_SSH_SERVICE_CONNECTION) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
                continue;
            }
            return NETNOX_RETURN_FAILED;
        }
        case NETNOX_SSH_MSG_USERAUTH_REQUEST:
            if(s->userauth_service_ready == 0u) {
                return NETNOX_RETURN_FAILED;
            }
            if(srv_handle_userauth_request(s, payload, payload_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            continue;
        case NETNOX_SSH_MSG_CHANNEL_OPEN: {
            uint32_t off = 1u;
            const uint8_t * typ = NULL;
            uint32_t typ_len = 0u;
            uint32_t sender = 0u;
            uint32_t client_init_win = 0u;
            uint32_t client_max_pkt = 0u;
            if(s->authenticated == 0u || s->connection_service_ready == 0u) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &typ, &typ_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_u32(payload, payload_len, &off, &sender) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_u32(payload, payload_len, &off, &client_init_win) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(netnox_ssh_payload_read_u32(payload, payload_len, &off, &client_max_pkt) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(typ_len == strlen(NETNOX_SSH_CHANNEL_TYPE_SESSION) &&
               memcmp(typ, NETNOX_SSH_CHANNEL_TYPE_SESSION, typ_len) == 0) {
                s->remote_window_size = client_init_win;
                s->remote_max_packet_size = (client_max_pkt != 0u) ? client_max_pkt : NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE;
                if(srv_send_channel_open_confirmation(s, sender) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
                s->channel_open = 1u;
                continue;
            }
            return NETNOX_RETURN_FAILED;
        }
        case NETNOX_SSH_MSG_CHANNEL_REQUEST: {
            uint32_t off = 1u;
            uint32_t chan = 0u;
            const uint8_t * req = NULL;
            uint32_t req_len = 0u;
            uint8_t want_reply = 0u;
            if(s->channel_open == 0u) {
                continue;
            }
            if(netnox_ssh_payload_read_u32(payload, payload_len, &off, &chan) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(chan != s->local_channel_id) {
                continue;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &req, &req_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(off >= payload_len) {
                return NETNOX_RETURN_FAILED;
            }
            want_reply = payload[off++];
            if(req_len == strlen(NETNOX_SSH_CHANNEL_REQ_EXEC) && memcmp(req, NETNOX_SSH_CHANNEL_REQ_EXEC, req_len) == 0) {
                const uint8_t * cmd = NULL;
                uint32_t cmd_len = 0u;
                char cmdbuf[NETNOX_SSH_MAX_COMMAND_LEN + 1u];
                if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &cmd, &cmd_len) != NETNOX_RETURN_SUCCESS) {
                    if(want_reply != 0u) {
                        (void)srv_send_channel_failure(s);
                    }
                    continue;
                }
                if(cmd_len > NETNOX_SSH_MAX_COMMAND_LEN) {
                    if(want_reply != 0u) {
                        (void)srv_send_channel_failure(s);
                    }
                    continue;
                }
                memcpy(cmdbuf, cmd, cmd_len);
                cmdbuf[cmd_len] = '\0';
                if(want_reply != 0u) {
                    if(srv_send_channel_success(s) != NETNOX_RETURN_SUCCESS) {
                        return NETNOX_RETURN_FAILED;
                    }
                }
#ifndef _WIN32
                if(srv_run_exec_unix(s, cmdbuf) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
#else
                if(srv_run_exec_win32(s, cmdbuf) != NETNOX_RETURN_SUCCESS) {
                    return NETNOX_RETURN_FAILED;
                }
#endif
                continue;
            }
            if(req_len == strlen(NETNOX_SSH_CHANNEL_REQ_SHELL) && memcmp(req, NETNOX_SSH_CHANNEL_REQ_SHELL, req_len) == 0) {
                if(want_reply != 0u) {
                    (void)srv_send_channel_failure(s);
                }
                continue;
            }
            if(req_len == strlen(NETNOX_SSH_CHANNEL_REQ_SUBSYSTEM) &&
               memcmp(req, NETNOX_SSH_CHANNEL_REQ_SUBSYSTEM, req_len) == 0) {
                const uint8_t * sub = NULL;
                uint32_t sub_len = 0u;
                if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &sub, &sub_len) != NETNOX_RETURN_SUCCESS) {
                    if(want_reply != 0u) {
                        (void)srv_send_channel_failure(s);
                    }
                    continue;
                }
                if(sub_len == strlen(NETNOX_SSH_SUBSYSTEM_SFTP) &&
                   memcmp(sub, NETNOX_SSH_SUBSYSTEM_SFTP, sub_len) == 0) {
                    /* SFTP subsystem: scaffolding — reject until SFTP layer is implemented. */
                    if(want_reply != 0u) {
                        (void)srv_send_channel_failure(s);
                    }
                    continue;
                }
                if(want_reply != 0u) {
                    (void)srv_send_channel_failure(s);
                }
                continue;
            }
            if(want_reply != 0u) {
                (void)srv_send_channel_failure(s);
            }
            continue;
        }
        case NETNOX_SSH_MSG_CHANNEL_DATA: {
            uint32_t off = 1u;
            uint32_t recipient = 0u;
            const uint8_t * dat = NULL;
            uint32_t dat_len = 0u;
            if(netnox_ssh_payload_read_u32(payload, payload_len, &off, &recipient) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(recipient != s->local_channel_id) {
                continue;
            }
            if(netnox_ssh_payload_read_string_view(payload, payload_len, &off, &dat, &dat_len) != NETNOX_RETURN_SUCCESS) {
                return NETNOX_RETURN_FAILED;
            }
            if(s->local_window_size >= dat_len) {
                s->local_window_size -= dat_len;
            }
            (void)srv_maybe_window_adjust(s);
            continue;
        }
        case NETNOX_SSH_MSG_CHANNEL_EOF:
        case NETNOX_SSH_MSG_CHANNEL_CLOSE:
            s->channel_open = 0u;
            return NETNOX_RETURN_SUCCESS;
        default:
            SRVDBG("unhandled msg %u", (unsigned)payload[0]);
            continue;
        }
    }
    return NETNOX_RETURN_SUCCESS;
}
