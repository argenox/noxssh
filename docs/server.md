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
