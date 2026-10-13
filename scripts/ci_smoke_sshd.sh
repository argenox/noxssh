#!/usr/bin/env bash
# Linux integration smoke. Creates a disposable OS account; never edits a real user's authorized_keys.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NOXSSH="$ROOT/bin/noxssh"
NOXSSHD="$ROOT/bin/noxsshd"
command -v sudo >/dev/null || { echo 'sudo required for isolated account smoke' >&2; exit 1; }
sudo -n true || { echo 'passwordless sudo required for isolated account smoke' >&2; exit 1; }
[[ -x "$NOXSSH" && -x "$NOXSSHD" ]]
KEYDIR="$(mktemp -d)"
HOSTDIR="$(sudo mktemp -d)"
USER_NAME="noxsshci${RANDOM}"
PORT="${NOXSSH_SMOKE_PORT:-4022}"
DAEMON_PID=''
cleanup() {
  if [[ -n "$DAEMON_PID" ]]; then kill "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; fi
  sudo userdel -r "$USER_NAME" >/dev/null 2>&1 || true
  sudo rm -rf -- "$HOSTDIR"
  rm -rf -- "$KEYDIR"
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/id"
sudo useradd -m -U -s /bin/sh "$USER_NAME"
sudo install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
sudo install -m 600 -o "$USER_NAME" -g "$USER_NAME" "$KEYDIR/id.pub" "/home/$USER_NAME/.ssh/authorized_keys"
sudo timeout 60s "$NOXSSHD" -p "$PORT" --host-key "$HOSTDIR/seed" >"$KEYDIR/server.log" 2>&1 &
DAEMON_PID=$!
sleep 1
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEYDIR/id" -p "$PORT")
OUT="$(ssh "${SSH_OPTS[@]}" "$USER_NAME@127.0.0.1" 'printf ci_exec_ok')"
[[ "$OUT" == 'ci_exec_ok' ]]
OUT="$(printf 'printf ci_shell_ok; exit\n' | ssh -tt "${SSH_OPTS[@]}" "$USER_NAME@127.0.0.1")"
[[ "$OUT" == *ci_shell_ok* ]]
if ssh "${SSH_OPTS[@]}" "no_such_noxssh_user@127.0.0.1" 'printf bad' >/dev/null 2>&1; then
  echo 'invalid account authenticated' >&2; exit 1
fi
OUT="$("$NOXSSH" --batch --strict-host-key-checking no -i "$KEYDIR/id" -p "$PORT" "$USER_NAME@127.0.0.1" 'printf ci_noxssh_ok')"
[[ "$OUT" == *ci_noxssh_ok* ]]
echo 'ci_smoke_sshd: exec, PTY shell, invalid account, NoxSSH client passed'
