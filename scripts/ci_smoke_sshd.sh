#!/usr/bin/env bash
# Smoke: noxsshd + noxssh to localhost (Unix).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NOXSSH="${ROOT}/bin/noxssh"
NOXSSHD="${ROOT}/bin/noxsshd"
if [[ ! -f "${NOXSSH}" ]] || [[ ! -f "${NOXSSHD}" ]]; then
  echo "ci_smoke_sshd: expected ${NOXSSH} and ${NOXSSHD}" >&2
  exit 1
fi
KEYFILE="$(mktemp)"
trap 'rm -f "${KEYFILE}"; kill "${NOXSSHD_PID:-}" 2>/dev/null || true' EXIT
if ! head -c 32 /dev/urandom > "${KEYFILE}" 2>/dev/null; then
  openssl rand -out "${KEYFILE}" 32
fi
PORT="${NOXSSH_SMOKE_PORT:-4022}"
"${NOXSSHD}" -p "${PORT}" --password smoketest --host-key "${KEYFILE}" &
NOXSSHD_PID=$!
sleep 2
OUT="$("${NOXSSH}" -p "${PORT}" -w smoketest user@127.0.0.1 "echo ci_ok" || true)"
if [[ "${OUT}" != *"ci_ok"* ]]; then
  echo "ci_smoke_sshd: expected ci_ok in output, got: ${OUT}" >&2
  exit 1
fi
kill "${NOXSSHD_PID}" 2>/dev/null || true
wait "${NOXSSHD_PID}" 2>/dev/null || true
echo "ci_smoke_sshd: ok"
