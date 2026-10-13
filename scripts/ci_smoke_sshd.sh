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
  local status=$?
  if ((status != 0)); then
    echo "ci_smoke_sshd failed at $(date -u +%FT%TZ), status=$status" >&2
    if [[ -f "$KEYDIR/server.log" ]]; then cat "$KEYDIR/server.log" >&2; fi
  fi
  if [[ -n "$DAEMON_PID" ]]; then kill "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; fi
  sudo userdel -r "$USER_NAME" >/dev/null 2>&1 || true
  sudo rm -rf -- "$HOSTDIR"
  rm -rf -- "$KEYDIR"
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/id"
echo "ci_smoke_sshd: account setup $(date -u +%FT%TZ)"
sudo useradd -m -U -s /bin/sh "$USER_NAME"
sudo install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
sudo install -m 600 -o "$USER_NAME" -g "$USER_NAME" "$KEYDIR/id.pub" "/home/$USER_NAME/.ssh/authorized_keys"
echo "ci_smoke_sshd: daemon start $(date -u +%FT%TZ)"
sudo env NETNOX_SSH_DEBUG=1 timeout 180s "$NOXSSHD" -p "$PORT" --host-key "$HOSTDIR/seed" >"$KEYDIR/server.log" 2>&1 &
DAEMON_PID=$!
sleep 1
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$KEYDIR/id" -p "$PORT")
echo "ci_smoke_sshd: OpenSSH exec $(date -u +%FT%TZ)"
OUT="$(ssh "${SSH_OPTS[@]}" "$USER_NAME@127.0.0.1" 'printf ci_exec_ok')"
[[ "$OUT" == 'ci_exec_ok' ]]
echo "ci_smoke_sshd: quiet child after output EOF $(date -u +%FT%TZ)"
if ssh "${SSH_OPTS[@]}" "$USER_NAME@127.0.0.1" 'exec 0<&- 1>&- 2>&-; sleep 11; exit 9' > /dev/null 2>"$KEYDIR/quiet.err"; then
  echo 'quiet child returned success instead of status 9' >&2; exit 1
else
  rc=$?
  if ((rc != 9)); then cat "$KEYDIR/quiet.err" >&2; echo "quiet child returned status $rc instead of 9" >&2; exit 1; fi
fi
echo "ci_smoke_sshd: OpenSSH PTY $(date -u +%FT%TZ)"
OUT="$(printf 'printf ci_shell_ok; exit\n' | ssh -tt "${SSH_OPTS[@]}" "$USER_NAME@127.0.0.1")"
[[ "$OUT" == *ci_shell_ok* ]]
if ssh "${SSH_OPTS[@]}" "no_such_noxssh_user@127.0.0.1" 'printf bad' >/dev/null 2>&1; then
  echo 'invalid account authenticated' >&2; exit 1
fi
echo "ci_smoke_sshd: NoxSSH exec $(date -u +%FT%TZ)"
if ! OUT="$("$NOXSSH" -d --batch --strict-host-key-checking no -i "$KEYDIR/id" -p "$PORT" "$USER_NAME@127.0.0.1" 'printf ci_noxssh_ok' 2>&1)"; then
  echo "NoxSSH client failed: $OUT" >&2
  cat "$KEYDIR/server.log" >&2
  exit 1
fi
[[ "$OUT" == *ci_noxssh_ok* ]]
echo 'ci_smoke_sshd: exec, PTY shell, invalid account, NoxSSH client passed'
