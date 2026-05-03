/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*/

#ifndef _NOXSSH_DAEMON_RUNTIME_H_
#define _NOXSSH_DAEMON_RUNTIME_H_

#include <stdint.h>
#include "noxssh_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Listen on @p bind_host : @p port and serve one client at a time (sequential).
 *
 * @p bind_host may be NULL for all interfaces. @p host_ed25519_seed is always
 * 32 bytes (Ed25519 seed); generate or load before calling.
 */
int noxsshd_listen_loop(const char * bind_host,
                        uint16_t port,
                        const char * password,
                        const uint8_t host_ed25519_seed[32]);

#ifdef __cplusplus
}
#endif

#endif /* _NOXSSH_DAEMON_RUNTIME_H_ */
