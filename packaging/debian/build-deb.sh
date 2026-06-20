#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
OUTPUT_DIR="${1:-${ROOT_DIR}/dist/debian}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: Debian packages must be built on Linux." >&2
    exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: dpkg-deb not found. Install dpkg (e.g. apt install dpkg)." >&2
    exit 1
fi

VERSION="$(
    python3 - <<'PY'
import pathlib
import re
import sys

header = pathlib.Path("client/version.h").read_text(encoding="utf-8")
match = re.search(r'NOXSSH_VERSION_STRING\s+"([^"]+)"', header)
if not match:
    sys.exit("Could not find NOXSSH_VERSION_STRING in client/version.h")
print(match.group(1))
PY
)"

cd "${ROOT_DIR}"

git submodule update --init --recursive

cmake -S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" --parallel
cmake --build "${BUILD_DIR}" --target package

mkdir -p "${OUTPUT_DIR}"
shopt -s nullglob
deb_files=("${BUILD_DIR}"/*.deb)
if [[ ${#deb_files[@]} -eq 0 ]]; then
    echo "ERROR: No .deb package was produced in ${BUILD_DIR}." >&2
    exit 1
fi

for deb in "${deb_files[@]}"; do
    cp -a "${deb}" "${OUTPUT_DIR}/"
done

printf 'Built Debian package(s) for noxssh v%s:\n' "${VERSION}"
ls -1 "${OUTPUT_DIR}"/*.deb
