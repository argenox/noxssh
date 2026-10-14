# Linux server

`noxsshd` is an opt-in Linux SSH server. The packaged service is disabled by default.
It binds to `127.0.0.1:2222` unless `-b` and `-p` are supplied. The
MPUNoxV image can retain OpenSSH while this server is qualified.

The server accepts Ed25519 public keys only. The requested username must
resolve to a local account with a usable shell. It reads that account's
`~/.ssh/authorized_keys`, accepting plain `ssh-ed25519` lines without key
options. Home, `.ssh`, and `authorized_keys` must be owned by the account
or root and not writable by group or other users. The key file must be
regular and at most 64 KiB. Successful sessions use that account's UID,
GID, groups, home directory, and shell.

Create a protected host key directory before starting the server:

```sh
install -d -m 0700 /etc/noxssh
noxsshd -b 0.0.0.0 -p 2222
```

On its first start, the daemon creates `/etc/noxssh/host_ed25519_seed` with
mode `0600` using Linux `getrandom()`. The 32-byte seed is reused on future
starts; back it up as a secret if clients pin the host identity. A supplied
`--host-key` must be an absolute path under a directory owned by the daemon
and not group/other writable. The server refuses an unsafe or malformed key.

The server opens and validates the parent directory descriptor once, then uses
descriptor-relative seed reads, exclusive creation and failure cleanup. Directory
fsync uses that same descriptor, so replacing the parent pathname after validation
cannot redirect these operations. Parent and seed final-component symlinks are
refused. Seed ownership, private permissions and the existing 32-byte format are
preserved. A directory-fsync failure returns failure while retaining the complete
seed; a later invocation reuses it rather than silently changing host identity.

Focused synthetic fixtures exercise directory replacement, existing-key reuse,
creation, cleanup and injected I/O failures without using real keys or a daemon:

```sh
python3 scripts/test_host_seed_dirfd.py
```

This compiles only the actual seed functions with `-Wall -Wextra -Werror` in a
temporary fixture directory. It does not replace full server, CI or target testing.

`noxsshd --check-user root` returns success only if root's account and
`authorized_keys` currently permit an Ed25519 key. It does not create a host
key or bind a socket. On the trusted UART console, run
`noxsshd --print-host-public-key` to create or read the persistent host seed
and print only its OpenSSH public key. `ssh-keygen -lf -` can display its
fingerprint, and the public key can be pinned in the client's `known_hosts`
before the first network connection. Never transfer the host seed itself.

The current server supports one session channel per connection, remote
commands, a shell, optional PTY, terminal resize, stdin/stdout/stderr,
and `exit-status`. It permits four concurrent connections. Idle sessions
close after 30 minutes, and connections close at the 256 MiB rekey limit
until in-session rekey is implemented. It does not offer SFTP, forwarding,
password authentication, or every SSH terminal-mode control.

An individual exec command is limited to 512 bytes. Split longer diagnostics
into separate requests. A non-login exec shell may need an explicit PATH
including `/usr/sbin` and `/sbin` for tools such as `ip` and `ethtool`.

## KC705 qualification status

The `04d265b` server binary ran on the KC705 RV64 Linux system over UART
controlled **loopback** `127.0.0.1:2222`. Remote exec (`id`, `uname`), PTY,
an 11-second quiet command returning status 9, invalid-user rejection, and
wrong-key rejection passed. The host seed was stored on SD with owner root
and mode `0600`; its public-key fingerprint was
`SHA256:1Cb2ywW9q2npFNJLYnYhWWgCRALJVdY5Pj1WiD33SbM`. The operator
reported cleanup status 0, removal of the temporary client keys and PC
authorization line, and daemon shutdown. The UART evidence is at
`E:/MPUNoxV_build_artifacts/ethernet_20261012/noxssh-loopback-04d265b.log`.

### Physical Ethernet trials, 2026-10-13

The final Yocto-pinned source `1ef8774` ran on the actual KC705, Linux
6.18.39 with both harts at 200 MHz, through the board's RJ45 connector and
our GMII MAC/PHY. Both the coherent-DMA and corrected PIO configurations
negotiated 1000 Mb/s full duplex with the Marvell 88E1111 at MDIO address 7.

The physical helper passed trusted-host Ed25519 authentication, exec, PTY,
an 11-second quiet command returning 9, invalid-account/key rejection, and
262144-byte encrypted upload/download with exact checksum agreement.
`--check-user root` was exercised on the real board; the public host key
was obtained over the trusted UART path. Its fingerprint remained
`SHA256:1Cb2ywW9q2npFNJLYnYhWWgCRALJVdY5Pj1WiD33SbM` after the next
JTAG Linux reboot. NoxSSH was enabled in persistent `/etc/default/noxsshd`
on port 2222 and started automatically after that reboot; the physical PIO
helper passed without launching a manual daemon.

Evidence under `E:/MPUNoxV_build_artifacts/ethernet_qualification_20261013`:

- `dma-hpm-7e390d9-noxssh-physical-supplier/result.json`:
  transfer SHA-256 `4a26d10d0747718f9b3d0788eeab640357c2e06d79e08747ac787662764a99b7`.
- `pio-v2-hpm-7e390d9-noxssh-persistent/result.json`:
  transfer SHA-256 `9e2675e51d78132dfe1d4da1d8875dcb13e1b5534bedd8f45f176e46eb1cff85`.

RX busy/buffer drops were recorded. These tests prove working SSH over
physical Ethernet, not line-rate, zero-drop operation, complete link-loss
recovery, power-cycle persistence or autonomous FPGA flash configuration.

### Quiet exec keepalive correction (source candidate)

The Unix exec/PTY session has its own receive loop. Source through `2e294de`
answered unsupported global requests in the outer connection loop but
dropped them inside a running session. OpenSSH sends a global
`keepalive@openssh.com` request with a requested reply and counts missing
replies toward its `ServerAliveCountMax` timeout. A failure reply is valid
liveness evidence and does not grant the unsupported operation. See the
[OpenSSH 9.5 client implementation](https://github.com/openssh/openssh-portable/blob/V_9_5_P1/clientloop.c#L444-L483).

The source fix uses one validated global-request handler in both loops.
It sends no reply for want-reply zero and `SSH_MSG_REQUEST_FAILURE` for a
nonzero flag. Truncated headers, missing boolean and overflowing string
lengths fail closed; transport send failures propagate. Request-specific
arguments for unsupported requests remain opaque, and forwarding stays
unsupported. No authentication, credential, host seed, crypto or client
keepalive setting changes are part of this correction. The correction is
for the Unix server, not the unused Windows one-shot `_popen` implementation.

Offline test:

```sh
python3 -B scripts/test_session_keepalive.py --fixture-parent <private-scratch>
```

This compiles the actual parser and both actual dispatch blocks with
`-Wall -Wextra -Werror`, using a simulated send transport. It checks repeated
quiet-session probes, want-reply zero/one/nonzero, unsupported request
arguments, send failure, and malformed/truncated/overflow requests. It
does not establish encrypted transport, a Unix child or RV64 execution.

Root must compile the full Linux server and run the existing isolated-account
`scripts/ci_smoke_sshd.sh`. That smoke now includes a quiet 45-second command
with stdout still open and a quiet 45-second output-EOF child returning 9,
both with `ServerAliveInterval=10` and `ServerAliveCountMax=3`. The former
11-second smoke without keepalive probes did not cover this failure.

On 2026-10-14, the board operator reported a read-only
`sleep 45; printf QUIET_COMMAND_COMPLETED` reproducer exiting 255 after
45.391 seconds with no stdout under those same keepalive settings. This is
pre-fix reproduction, not validation of a new binary. After source and
binary qualification, root should repeat that exact command through the
existing trusted-host/public-key SSH policy and require exit 0 plus the
exact marker; also check the output-EOF case returns 9 rather than 255.
The root-owned updater must not resume from an ambiguous timeout without
its separate checkpoint/card-state review.
