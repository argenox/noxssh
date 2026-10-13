# NoxSSH server and embedded integration

## Overview

`netnox_ssh_server_t` (`common/noxssh_server.h`) implements one SSH-2 **server**
role over a byte stream. It uses the same negotiated algorithms as the stock
client (`curve25519-sha256`, `ssh-ed25519`, `aes128-ctr`, `hmac-sha2-256`).

The reference daemon **`noxsshd`** (`server/main.c`) binds a TCP socket and
calls `netnox_ssh_server_serve_one()` per accepted connection.

## Transport (required)

Implement `netnox_ssh_transport_send_t` and `netnox_ssh_transport_recv_t` with
blocking semantics matching the TCP socket behavior of the CLI client. The
server core never opens sockets itself.

## Host key

Call `netnox_ssh_server_set_host_ed25519_seed()` with a 32-byte Ed25519 seed
(RFC 8032 private key format as used by NoxTLS), or
`netnox_ssh_server_generate_host_ed25519_key()` for ephemeral keys.

## Authentication

Use `netnox_ssh_server_set_publickey_callback()` to decide whether the
requested username and Ed25519 public key are authorized. The Linux daemon
checks the local account and protected `authorized_keys` before signature
verification. Password authentication is not implemented. See
[Linux server integration](server.md) for its account and host-key rules.

## Subsystems and PTY

- On Linux, **exec**, **shell**, optional **PTY**, terminal resize and
  exit-status forwarding are implemented using OS account/session support.
  An individual exec command is limited to 512 bytes.
- **subsystem sftp**: rejected (scaffolding only); SFTP framing can be added
  later.

## Optional hooks

`server/embedded_adapter.h` contains future/platform-specific hook typedefs;
they are not an implemented RTOS or bare-metal session backend. The current
server uses a blocking OS CSPRNG (Linux `getrandom`) and fails instead of
falling back to `rand()`. A non-Linux embedded port also needs monotonic time,
authorization and application/session adapters. Stream callbacks alone do
not establish a complete portable server implementation.

## Build without the daemon

The `noxsshd` target is in `server/`. The static library `netnox_ssh` always
includes `noxssh_server.c`; omit linking `noxsshd` if you only need the client.
