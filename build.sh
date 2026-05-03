#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
BIN_DIR="${ROOT_DIR}/bin"
BUILD_TYPE="${1:-Release}"

mkdir -p "${BIN_DIR}"

git -C "${ROOT_DIR}" submodule update --init --recursive

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
cmake --build "${BUILD_DIR}"

printf 'Build complete (noxssh client + noxsshd server). Binaries are in: %s\n' "${BIN_DIR}"
if [ ! -f "${BIN_DIR}/noxssh" ]; then
  printf 'Warning: expected %s/noxssh\n' "${BIN_DIR}" >&2
fi
if [ ! -f "${BIN_DIR}/noxsshd" ]; then
  printf 'Warning: expected %s/noxsshd\n' "${BIN_DIR}" >&2
fi
