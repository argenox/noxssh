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
* File:    noxssh_common_config.h
* Summary: NoxSSH common SSH configuration defaults
*
*/

/**
 * @file noxssh_common_config.h
 * @brief NoxSSH common configurable defaults.
 */

#ifndef _NOXSSH_COMMON_CONFIG_H_
#define _NOXSSH_COMMON_CONFIG_H_

/* Core size limits */
#ifndef NETNOX_SSH_MAX_IDENT_LEN
#define NETNOX_SSH_MAX_IDENT_LEN (255u)
#endif
#ifndef NETNOX_SSH_MAX_BANNER_LINES
#define NETNOX_SSH_MAX_BANNER_LINES (8u)
#endif
#ifndef NETNOX_SSH_MAX_USERNAME_LEN
#define NETNOX_SSH_MAX_USERNAME_LEN (64u)
#endif
#ifndef NETNOX_SSH_MAX_HOST_LEN
#define NETNOX_SSH_MAX_HOST_LEN (255u)
#endif
#ifndef NETNOX_SSH_MAX_COMMAND_LEN
#define NETNOX_SSH_MAX_COMMAND_LEN (512u)
#endif
#ifndef NETNOX_SSH_MAX_DATA_LEN
#define NETNOX_SSH_MAX_DATA_LEN (4096u)
#endif
/* RFC 4253 Section 6.1: implementations MUST process packets with total size
 * <= 35000 bytes and uncompressed payload length <= 32768 bytes. */
#ifndef NETNOX_SSH_MAX_PACKET_LEN
#define NETNOX_SSH_MAX_PACKET_LEN (35000u)
#endif
/* KEXINIT is a single payload; RFC 4253 mandates supporting payloads up to 32768. */
#ifndef NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN
#define NETNOX_SSH_MAX_KEXINIT_PAYLOAD_LEN (32768u)
#endif
#ifndef NETNOX_SSH_MAX_PASSWORD_LEN
#define NETNOX_SSH_MAX_PASSWORD_LEN (128u)
#endif
#ifndef NETNOX_SSH_MAX_HOST_KEY_BLOB_LEN
#define NETNOX_SSH_MAX_HOST_KEY_BLOB_LEN (2048u)
#endif

/* KEX algorithm offers / requirements */
#ifndef NETNOX_SSH_KEX_ALG_LIST
#define NETNOX_SSH_KEX_ALG_LIST "curve25519-sha256,diffie-hellman-group14-sha256"
#endif
#ifndef NETNOX_SSH_HOST_KEY_ALG_LIST
#define NETNOX_SSH_HOST_KEY_ALG_LIST "ssh-ed25519,rsa-sha2-256,ssh-rsa"
#endif
#ifndef NETNOX_SSH_CIPHER_ALG_LIST
#define NETNOX_SSH_CIPHER_ALG_LIST "aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com"
#endif
#ifndef NETNOX_SSH_MAC_ALG_LIST
#define NETNOX_SSH_MAC_ALG_LIST "hmac-sha2-256,hmac-sha1"
#endif
#ifndef NETNOX_SSH_COMPRESSION_ALG_LIST
#define NETNOX_SSH_COMPRESSION_ALG_LIST "none"
#endif

#ifndef NETNOX_SSH_REQUIRED_KEX_ALG
#define NETNOX_SSH_REQUIRED_KEX_ALG "curve25519-sha256"
#endif
#ifndef NETNOX_SSH_REQUIRED_HOST_KEY_ALG
#define NETNOX_SSH_REQUIRED_HOST_KEY_ALG "ssh-ed25519"
#endif
#ifndef NETNOX_SSH_REQUIRED_CIPHER_ALG
#define NETNOX_SSH_REQUIRED_CIPHER_ALG "aes128-ctr"
#endif
#ifndef NETNOX_SSH_REQUIRED_MAC_ALG
#define NETNOX_SSH_REQUIRED_MAC_ALG "hmac-sha2-256"
#endif
#ifndef NETNOX_SSH_REQUIRED_COMPRESSION_ALG
#define NETNOX_SSH_REQUIRED_COMPRESSION_ALG "none"
#endif

/* Channel/session defaults */
#ifndef NETNOX_SSH_CHANNEL_WINDOW_SIZE
#define NETNOX_SSH_CHANNEL_WINDOW_SIZE (65536u)
#endif
#ifndef NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE
#define NETNOX_SSH_CHANNEL_MAX_PACKET_SIZE (32768u)
#endif

#endif
