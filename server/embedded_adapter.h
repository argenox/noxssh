/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* @file embedded_adapter.h
* @brief Contract for embedding noxsshd / netnox_ssh_server on RTOS or bare-metal.
*
* The portable server core lives in @c netnox_ssh_server_t (noxssh_server.h):
* it only needs blocking @c send_cb / @c recv_cb over any byte stream (TCP,
* UART framing, custom link). Desktop daemons use POSIX or Winsock sockets
* behind those callbacks; embedded ports supply their own.
*
* Optional hooks (future / platform-specific):
* - Monotonic milliseconds for rekey and timeouts
* - CSPRNG for KEXINIT cookies and padding (today the stack uses @c rand() for
*   non-cryptographic SSH padding; replace with DRBG for hardened devices)
* - Subprocess / PTY: @c netnox_ssh_server_serve_one implements one-shot exec
*   on POSIX (@c fork/@c pipe) and @c _popen on Windows. Embedded targets without
*   a shell should wrap @c netnox_ssh_server_serve_one or add a compile-time
*   stub that maps CHANNEL_REQUEST exec to an application-defined handler.
*
* See docs/SERVER_EMBEDDED.md for integration steps.
*/

#ifndef _NOXSSH_EMBEDDED_ADAPTER_H_
#define _NOXSSH_EMBEDDED_ADAPTER_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Optional: monotonic time in milliseconds (for rekey / watchdogs). */
typedef uint64_t (*noxssh_embedded_monotonic_ms_fn)(void * user_data);

/** @brief Optional: fill @p buf with @p len bytes of cryptographic-quality random. */
typedef int (*noxssh_embedded_csprng_fn)(void * user_data, uint8_t * buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXSSH_EMBEDDED_ADAPTER_H_ */
