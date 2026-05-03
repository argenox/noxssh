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

`netnox_ssh_server_set_allowed_password()` configures a single shared password
accepted for **any** username (intended for lab / firmware shells). Extend the
server sources for per-user stores or public-key verification if needed.

## Subsystems and PTY

- **exec**: one-shot `sh -c` on Unix (`fork`/`pipe`) and `cmd /c` on Windows
  (`_popen`), stdout/stderr streamed as channel data.
- **shell** / **pty-req**: rejected with `CHANNEL_FAILURE` until PTY adapters
  are wired.
- **subsystem sftp**: rejected (scaffolding only); SFTP framing can be added
  later.

## Optional hooks

See `server/embedded_adapter.h` for typedefs describing optional monotonic
clock and CSPRNG hooks. The current implementation uses `rand()` for SSH
padding and KEXINIT cookies; hardened devices should replace these with NoxTLS
DRBG calls.

## Build without the daemon

The `noxsshd` target is in `server/`. The static library `netnox_ssh` always
includes `noxssh_server.c`; omit linking `noxsshd` if you only need the client.
