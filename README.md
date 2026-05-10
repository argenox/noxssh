# NoxSSH

[![Build](https://github.com/argenox/noxssh/actions/workflows/build.yml/badge.svg)](https://github.com/argenox/noxssh/actions/workflows/build.yml)
[![Release on tag](https://github.com/argenox/noxssh/actions/workflows/release-on-tag.yml/badge.svg)](https://github.com/argenox/noxssh/actions/workflows/release-on-tag.yml)

**NoxSSH** is a lightweight SSH client built on a standalone SSH common protocol layer and NoxTLS cryptographic primitives. It provides a simple CLI for connecting to SSH servers, with password authentication and support for both interactive sessions and one-shot remote command execution.

| | |
|---|---|
| **Version** | 0.1.0 |
| **Language** | C99 |
| **Build** | CMake 3.16+ |

---

## Features

- **SSH-2 client** — Version exchange, KEXINIT exchange, and session channel handling
- **Password authentication** — `ssh-userauth` with password method
- **Interactive or one-shot** — Connect for a shell or run a single remote command
- **Portable** — Windows (Winsock) and Unix (BSD sockets); transport is pluggable via callbacks
- **Small footprint** — Uses root `noxtls` crypto libraries;

---

## Quick start

### Prerequisites

- **CMake** 3.16 or newer  
- **C99** compiler (MSVC, GCC, Clang)  
- **NoxTLS submodule** — initialize before building:

```bash
git submodule update --init --recursive
```

### Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The `noxssh` executable is produced in `bin/` (or `build/bin/` depending on your generator).

### Usage

```text
Usage: noxssh [-h] [-d|-dd|-ddd] [-T] [--batch] [--strict-host-key] [--strict-host-key-checking mode] [--host-key-pin hex] [--known-hosts-file path] [--ed25519-key hex] [-i identity_file] [--connect-retries n] [--connect-timeout ms] [--io-timeout ms] [--server-alive-interval sec] [--server-alive-count-max n] [--rekey-interval sec] [-p port] [-w password] [user@]host [command]
```

| Example | Description |
|--------|-------------|
| `noxssh user@example.com` | Connect to `example.com` as `user` (default port 22) |
| `noxssh -p 2222 user@example.com` | Connect on port 2222 |
| `noxssh user@example.com "uname -a"` | Run a single command and exit |
| `noxssh -d user@example.com` | Basic debug logging |
| `noxssh -ddd user@example.com` | Packet-level debug logging |
| `noxssh -T user@example.com` | Request shell without PTY allocation |
| `noxssh --strict-host-key user@example.com` | Reject unknown host keys (no first-use prompt) |
| `noxssh --strict-host-key-checking accept-new user@example.com` | Auto-trust first-seen host keys, reject changed keys |
| `noxssh --host-key-pin <sha256hex> user@example.com` | Pin server host key fingerprint |
| `noxssh --known-hosts-file ~/.noxssh/known_hosts.custom user@example.com` | Use custom known_hosts path |
| `noxssh --ed25519-key <64hexseed> user@example.com` | Try Ed25519 publickey auth |
| `noxssh -i id_ed25519 user@example.com` | Load Ed25519 key from file (hex seed or unencrypted OpenSSH key) |
| `noxssh --server-alive-interval 30 user@example.com` | Send SSH keepalive every 30s of idle I/O |
| `noxssh --server-alive-interval 30 --server-alive-count-max 3 user@example.com` | Drop dead idle sessions after 3 unanswered keepalives |
| `noxssh --rekey-interval 900 user@example.com` | Trigger transport key re-exchange every 15 minutes |
| `noxssh --batch --connect-retries 3 --connect-timeout 5000 --io-timeout 10000 user@example.com "uptime"` | Non-interactive mode with retries and timeouts |

If `user@` is omitted, the default username is `user`. You are prompted for the password when using password authentication unless `-w` is provided. Use `-T` to disable PTY allocation (like OpenSSH), which is useful for non-interactive/automation scenarios. On connect, `noxssh` prints the server host-key fingerprint and enforces trust via `~/.noxssh/known_hosts` (TOFU prompt by default, configurable with `--strict-host-key-checking yes|no|accept-new|ask`, or strict reject mode via `--strict-host-key`). You can also pin an expected fingerprint with `--host-key-pin`.

When no explicit key is provided, `noxssh` also tries default identity paths (`~/.ssh/id_ed25519`, `~/.ssh/id_ed25519.seed`, `~/.noxssh/id_ed25519.seed`). Encrypted OpenSSH keys are detected but not yet supported.
If key auth is attempted first and rejected, `noxssh` falls back to prompting for password automatically.
In command mode (`noxssh user@host "cmd"`), the process exit code now mirrors the remote `exit-status` when provided by the server.
Use `--batch` to disable all interactive prompts (TOFU/password prompts); unknown hosts or missing credentials fail fast in this mode.
Use `--io-timeout` to bound socket recv/send stalls during handshake/auth/session.
Use `--server-alive-interval` to send periodic SSH keepalive packets (`SSH_MSG_IGNORE`) during idle sessions.
`--server-alive-count-max` controls how many unanswered keepalives are tolerated before disconnect (default: 3).
Use `--rekey-interval` to trigger periodic key re-exchange during long-lived sessions.
Server-initiated `SSH_MSG_KEXINIT` rekey events are also handled during active sessions.
`noxssh` also reads `~/.ssh/config` for `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `UserKnownHostsFile`, `StrictHostKeyChecking`, `BatchMode`, `ConnectTimeout`, `ServerAliveInterval`, `ServerAliveCountMax`, and `RekeyInterval` (CLI flags still take precedence).

---

## Repository layout

```text
noxssh/
├── client/                 # noxssh CLI application
│   ├── main.c              # CLI, TCP connect, and SSH common integration
│   └── CMakeLists.txt
├── common/                 # Standalone SSH protocol layer used by noxssh
│   ├── noxssh_common.c
│   ├── noxssh_common.h
│   └── noxssh_common_config.h
├── noxtls/                 # NoxTLS submodule (crypto)
├── bin/                    # Build output (noxssh executable)
├── CMakeLists.txt
├── CODE_STYLE_DOXYGEN.md   # Doxygen comment style for the codebase
└── README.md
```

The SSH protocol API is in `common/noxssh_common.h`. The CLI in `client/main.c` uses it with host TCP sockets and send/recv callbacks.

---

## Protocol library (noxssh_common)

The **noxssh_common** module provides a C API for SSH-2 client behavior without tying you to a specific transport:

- **Transport** — You supply `send` and `recv` callbacks (e.g., over a TCP socket or custom stream).
- **Crypto** — Uses root `noxtls` libraries directly;
- **Flow** — `netnox_ssh_client_connect` (version + KEXINIT), `netnox_ssh_client_authenticate` (password), `netnox_ssh_client_open_session`, then `netnox_ssh_client_exec` or send/recv channel data.

See `common/noxssh_common.h` for function and context documentation.

---

## License and attribution

Dual-licensed under GPL-2.0-or-later or commercial terms from Argenox Technologies LLC.
See `LICENSE.md`, `COPYING.md`, and source file SPDX headers for details.
