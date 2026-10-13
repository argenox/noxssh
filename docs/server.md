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
