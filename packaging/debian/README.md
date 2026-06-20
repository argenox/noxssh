# Debian packaging

NoxSSH uses CMake CPack to produce `.deb` packages on Linux.

## Prerequisites

- CMake 3.16+
- C compiler and build tools (`build-essential` on Debian/Ubuntu)
- `dpkg` (`apt install dpkg`)
- Initialized `noxtls` submodule

## Build locally

From the repository root:

```bash
./packaging/debian/build-deb.sh
```

Output directory: `dist/debian/`

Example package name: `noxssh_0.2.25_amd64.deb`

## Install

```bash
sudo dpkg -i dist/debian/noxssh_*_amd64.deb
```

The package installs:

- `/usr/bin/noxssh`
- `/usr/share/doc/noxssh/README.md`
- `/usr/share/doc/noxssh/LICENSE.md`
- `/usr/share/doc/noxssh/COPYING.md`

## Release workflow

The `Release on tag` GitHub Actions workflow builds Debian packages for Linux x86_64 and ARM64 and uploads them to the GitHub release as:

- `noxssh-linux-x86_64-v<version>.deb`
- `noxssh-linux-arm64-v<version>.deb`

Package version is taken from `client/version.h` (`NOXSSH_VERSION_STRING`), which must match the release tag (for example tag `v0.2.25`).
