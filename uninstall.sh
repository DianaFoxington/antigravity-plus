#!/usr/bin/env bash
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js (>= 18) is required." >&2
  exit 1
fi

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/cli.js" ]; then
  exec node "${SCRIPT_DIR}/cli.js" unpatch "$@"
fi

for CANDIDATE in "${HOME}/.gemini/antigravity-plus-src/cli.js" "${HOME}/.gemini/agy-unlocker/runtime/cli.js"; do
  if [ -f "${CANDIDATE}" ]; then
    exec node "${CANDIDATE}" unpatch "$@"
  fi
done

echo "Error: Could not find installed Antigravity Plus runtime to unpatch." >&2
exit 1
