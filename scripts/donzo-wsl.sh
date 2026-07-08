#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VENV_PYTHON="${REPO_ROOT}/.venv-wsl/bin/python"
SUDO_KEEPALIVE_PID=""

export PATH="${HOME}/.donzo/node/bin:${HOME}/.local/bin:${HOME}/.donzo/tools/bin:${HOME}/go/bin:${HOME}/.donzo/go/bin:${PATH}"
export CODEX_BIN="${CODEX_BIN:-${HOME}/.local/bin/codex}"
export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

if [[ ! -x "${VENV_PYTHON}" ]]; then
  echo "DONZO WSL venv is missing: ${VENV_PYTHON}" >&2
  echo "Run: bash scripts/install-donzo-tools-wsl.sh --profile deep" >&2
  exit 127
fi

if [[ -z "${DONZO_REQUIRE_SUDO:-}" && -f "${REPO_ROOT}/.env" ]]; then
  DONZO_REQUIRE_SUDO="$(
    "${VENV_PYTHON}" - "${REPO_ROOT}/.env" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

value = ""
for raw_line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("export "):
        line = line[len("export ") :].strip()
    if "=" not in line:
        continue
    key, raw_value = line.split("=", 1)
    if key.strip() != "DONZO_REQUIRE_SUDO":
        continue
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
print(value)
PY
  )"
  export DONZO_REQUIRE_SUDO
fi

cleanup() {
  if [[ -n "${SUDO_KEEPALIVE_PID}" ]]; then
    kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true
  fi
}

if [[ "${DONZO_REQUIRE_SUDO:-}" =~ ^(1|true|yes|on)$ ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "DONZO_REQUIRE_SUDO is set, but sudo is not installed." >&2
    exit 127
  fi
  echo "Refreshing sudo credentials for this DONZO run..." >&2
  sudo -v
  (
    while true; do
      sleep 60
      sudo -n true >/dev/null 2>&1 || exit 0
    done
  ) &
  SUDO_KEEPALIVE_PID="$!"
  trap cleanup EXIT INT TERM
  "${VENV_PYTHON}" -m donzo "$@"
  exit $?
fi

exec "${VENV_PYTHON}" -m donzo "$@"
