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
Usage: noxssh [-h] [-d|-dd|-ddd] [-p port] [-w password] [user@]host [command]
```

| Example | Description |
|--------|-------------|
| `noxssh user@example.com` | Connect to `example.com` as `user` (default port 22) |
| `noxssh -p 2222 user@example.com` | Connect on port 2222 |
| `noxssh user@example.com "uname -a"` | Run a single command and exit |
| `noxssh -d user@example.com` | Basic debug logging |
| `noxssh -ddd user@example.com` | Packet-level debug logging |

If `user@` is omitted, the default username is `user`. You are prompted for the password when using password authentication unless `-w` is provided.

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
