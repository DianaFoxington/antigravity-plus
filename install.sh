#!/usr/bin/env bash
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js (>= 18) is required. Install Node.js and try again." >&2
  exit 1
fi

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/cli.js" ]; then
  exec node "${SCRIPT_DIR}/cli.js" patch "$@"
fi

INSTALL_HOME="${HOME}/.gemini/antigravity-plus-src"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT

echo "Downloading Antigravity Plus from GitHub..."
curl -fsSL "https://github.com/DianaFoxington/antigravity-plus/archive/refs/heads/main.tar.gz" -o "${TMP_DIR}/src.tar.gz"
tar -xzf "${TMP_DIR}/src.tar.gz" -C "${TMP_DIR}"
EXTRACTED_DIR="$(find "${TMP_DIR}" -maxdepth 1 -mindepth 1 -type d | head -n 1)"

rm -rf "${INSTALL_HOME}"
mkdir -p "$(dirname "${INSTALL_HOME}")"
mv "${EXTRACTED_DIR}" "${INSTALL_HOME}"

exec node "${INSTALL_HOME}/cli.js" patch "$@"
