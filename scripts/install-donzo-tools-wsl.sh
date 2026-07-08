#!/usr/bin/env bash
set -Eeuo pipefail

# Installer only: installs DONZO's Python package and local recon tools.
# It does not run recon or touch any target.

PROFILE="deep"
REQUIRED_ONLY=false
SKIP_PYTHON_DEPS=false
SKIP_PREREQUISITES=false
SKIP_CODEX_CLI=false
NO_PATH_PERSIST=false
DRY_RUN=false
PIP_TIMEOUT="${PIP_TIMEOUT:-120}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-300}"
TOOL_INSTALL_TIMEOUT="${TOOL_INSTALL_TIMEOUT:-600}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOLS_ROOT="${HOME}/.donzo/tools"
TOOLS_BIN="${TOOLS_ROOT}/bin"
LOCAL_GO_ROOT="${HOME}/.donzo/go"
NODE_ROOT="${HOME}/.donzo/node"
GO_BIN="${HOME}/go/bin"
LOCAL_BIN="${HOME}/.local/bin"
VENV_DIR="${REPO_ROOT}/.venv-wsl"

export GOBIN="${GO_BIN}"
export PATH="${NODE_ROOT}/bin:${TOOLS_BIN}:${GO_BIN}:${LOCAL_BIN}:${LOCAL_GO_ROOT}/bin:${PATH}"
export PIP_DEFAULT_TIMEOUT="${PIP_DEFAULT_TIMEOUT:-${PIP_TIMEOUT}}"
export UV_HTTP_TIMEOUT="${UV_HTTP_TIMEOUT:-${HTTP_TIMEOUT}}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/install-donzo-tools-wsl.sh [options]

Options:
  --profile fast|normal|deep|all   Tool profile to install. Default: deep
  --required-only                  Install only tools required by the profile
  --skip-python-deps               Do not install DONZO Python package/deps
  --skip-prerequisites             Do not install apt prerequisites
  --skip-codex-cli                 Do not install or update Codex CLI
  --no-path-persist                Do not add tool paths to ~/.profile
  --dry-run                        Print commands without executing them
  -h, --help                       Show this help

Notes:
  Run this as your normal WSL user, not with sudo. The script asks sudo only
  when apt packages are needed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --required-only)
      REQUIRED_ONLY=true
      shift
      ;;
    --skip-python-deps)
      SKIP_PYTHON_DEPS=true
      shift
      ;;
    --skip-prerequisites)
      SKIP_PREREQUISITES=true
      shift
      ;;
    --skip-codex-cli)
      SKIP_CODEX_CLI=true
      shift
      ;;
    --no-path-persist)
      NO_PATH_PERSIST=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${PROFILE}" in
  fast|normal|deep|all) ;;
  *)
    echo "[ERROR] Invalid profile: ${PROFILE}" >&2
    exit 2
    ;;
esac

section() {
  printf '\n== %s ==\n' "$1"
}

info() {
  printf '[INFO] %s\n' "$1"
}

ok() {
  printf '[OK] %s\n' "$1"
}

warn() {
  printf '[WARN] %s\n' "$1" >&2
}

die() {
  printf '[ERROR] %s\n' "$1" >&2
  exit 1
}

run() {
  if [[ "${DRY_RUN}" == true ]]; then
    printf '[DRY] %q' "$1"
    shift
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

sudo_cmd() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

run_sudo() {
  if [[ "${DRY_RUN}" == true ]]; then
    printf '[DRY] sudo'
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi
  sudo_cmd "$@"
}

ensure_dir() {
  run mkdir -p "$1"
}

append_profile_path() {
  [[ "${NO_PATH_PERSIST}" == true ]] && return 0
  local profile_file
  local marker="# DONZO tool paths"
  local node_marker="# DONZO node/codex path"
  local node_line='export PATH="$HOME/.donzo/node/bin:$HOME/.local/bin:$PATH"'
  local line='export PATH="$HOME/.donzo/node/bin:$HOME/.donzo/tools/bin:$HOME/go/bin:$HOME/.local/bin:$HOME/.donzo/go/bin:$PATH"'
  for profile_file in "${HOME}/.profile" "${HOME}/.bashrc"; do
    if [[ -f "${profile_file}" ]] && grep -Fq "${marker}" "${profile_file}"; then
      if ! grep -Fq ".donzo/node/bin" "${profile_file}"; then
        if [[ "${DRY_RUN}" == true ]]; then
          info "Would add DONZO Node/Codex path to ${profile_file}"
          continue
        fi
        {
          printf '\n%s\n' "${node_marker}"
          printf '%s\n' "${node_line}"
        } >> "${profile_file}"
        ok "Added DONZO Node/Codex path to ${profile_file}"
      fi
      continue
    fi
    if [[ "${DRY_RUN}" == true ]]; then
      info "Would add DONZO tool paths to ${profile_file}"
      continue
    fi
    {
      printf '\n%s\n' "${marker}"
      printf '%s\n' "${line}"
    } >> "${profile_file}"
    ok "Added DONZO tool paths to ${profile_file}"
  done
}

python_version_ok() {
  local py="$1"
  "${py}" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 11) and sys.version_info.releaselevel == "final" else 1)
PY
}

python_bin=""

select_python() {
  if [[ -x "${VENV_DIR}/bin/python" ]] && python_version_ok "${VENV_DIR}/bin/python"; then
    python_bin="${VENV_DIR}/bin/python"
    return 0
  fi
  if have python3.11 && python_version_ok python3.11; then
    python_bin="python3.11"
    return 0
  fi
  if have python3 && python_version_ok python3; then
    python_bin="python3"
    return 0
  fi
  return 1
}

install_base_packages() {
  [[ "${SKIP_PREREQUISITES}" == true ]] && return 0
  section "Base apt packages"
  if ! have apt-get; then
    warn "apt-get not found; skipping apt prerequisites"
    return 0
  fi
  run_sudo apt-get update
  run_sudo apt-get install -y \
    ca-certificates \
    curl \
    git \
    unzip \
    tar \
    build-essential \
    software-properties-common \
    python3-pip
}

install_python311_with_apt() {
  [[ "${SKIP_PREREQUISITES}" == true ]] && return 1
  have apt-get || return 1

  section "Python 3.11"
  if have lsb_release && [[ "$(lsb_release -is 2>/dev/null)" == "Ubuntu" ]]; then
    local release
    release="$(lsb_release -rs 2>/dev/null || true)"
    if [[ "${release}" == "22.04" ]]; then
      info "Ubuntu 22.04 repo often exposes Python 3.11 rc builds; enabling deadsnakes for final Python 3.11"
      run_sudo add-apt-repository -y ppa:deadsnakes/ppa
      run_sudo apt-get update
    fi
  fi
  run_sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
}

install_python_with_uv() {
  have uv || return 1
  section "Python 3.11 via uv"
  info "Creating ${VENV_DIR}"
  run uv venv "${VENV_DIR}" --python 3.11
}

ensure_python() {
  if select_python; then
    ok "Using Python: $(${python_bin} --version 2>&1)"
    return 0
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    python_bin="python3.11"
    info "Would require Python 3.11 final"
    return 0
  fi

  if install_python_with_uv && select_python; then
    ok "Using Python: $(${python_bin} --version 2>&1)"
    return 0
  fi

  warn "uv managed Python failed or uv is unavailable; trying apt Python 3.11"
  install_python311_with_apt || true
  if select_python; then
    ok "Using Python: $(${python_bin} --version 2>&1)"
    return 0
  fi

  die "Python 3.11 final is required. Fix WSL network/sudo, then rerun this script."
}

install_python_deps() {
  [[ "${SKIP_PYTHON_DEPS}" == true ]] && return 0
  section "DONZO Python package"
  ensure_python
  if [[ "${python_bin}" != "${VENV_DIR}/bin/python" ]]; then
    run "${python_bin}" -m venv "${VENV_DIR}"
    python_bin="${VENV_DIR}/bin/python"
  fi
  cd "${REPO_ROOT}"
  run "${python_bin}" -m pip install --upgrade --timeout "${PIP_TIMEOUT}" --retries 10 pip setuptools wheel
  run "${python_bin}" -m pip install --timeout "${PIP_TIMEOUT}" --retries 10 -e ".[dev]"
}

ensure_pipx() {
  if have pipx; then
    return 0
  fi
  section "pipx"
  if have uv; then
    run uv tool install --force pipx
  else
    run python3 -m pip install --user --upgrade --timeout "${PIP_TIMEOUT}" --retries 10 pipx
  fi
  export PATH="${LOCAL_BIN}:${PATH}"
}

go_version_ok() {
  have go || return 1
  local version
  version="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
  python3 - "$version" <<'PY' >/dev/null 2>&1
import sys
parts = sys.argv[1].split(".")
try:
    major, minor = int(parts[0]), int(parts[1])
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if (major, minor) >= (1, 22) else 1)
PY
}

install_go() {
  if go_version_ok; then
    ok "Using Go: $(go version)"
    return 0
  fi

  section "Go toolchain"
  ensure_dir "${LOCAL_GO_ROOT}"
  local tmp archive url
  tmp="$(mktemp -d)"
  archive="$(
    curl -fsSL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" "https://go.dev/dl/?mode=json" |
      python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(f["filename"] for r in data if r.get("stable") for f in r["files"] if f["os"]=="linux" and f["arch"]=="amd64" and f["kind"]=="archive"))'
  )"
  url="https://go.dev/dl/${archive}"
  info "Downloading ${url}"
  run curl -fL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" -o "${tmp}/${archive}" "${url}"
  run rm -rf "${LOCAL_GO_ROOT}"
  ensure_dir "${LOCAL_GO_ROOT}"
  run tar -C "${LOCAL_GO_ROOT}" --strip-components=1 -xzf "${tmp}/${archive}"
  run rm -rf "${tmp}"
  export PATH="${LOCAL_GO_ROOT}/bin:${PATH}"
  ok "Using Go: $(${LOCAL_GO_ROOT}/bin/go version)"
}

install_nodejs() {
  if have node && have npm; then
    ok "Using Node: $(node --version)"
    return 0
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    info "Would install latest Node.js LTS to ${NODE_ROOT}"
    return 0
  fi

  section "Node.js"
  ensure_dir "${NODE_ROOT}"
  local node_version arch name tmp archive
  arch="x64"
  node_version="$(
    curl -fsSL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" \
      "https://nodejs.org/dist/index.json" |
      python3 -c 'import json,sys; data=json.load(sys.stdin); lts=[x for x in data if x.get("lts")]; print((lts or data)[0]["version"])'
  )"
  name="node-${node_version}-linux-${arch}"
  archive="${name}.tar.xz"
  tmp="$(mktemp -d)"
  info "Downloading Node.js ${node_version}"
  run curl -fL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" \
    -o "${tmp}/${archive}" "https://nodejs.org/dist/${node_version}/${archive}"
  run rm -rf "${NODE_ROOT}"
  ensure_dir "${NODE_ROOT}"
  run tar -C "${NODE_ROOT}" --strip-components=1 -xJf "${tmp}/${archive}"
  run rm -rf "${tmp}"
  export PATH="${NODE_ROOT}/bin:${PATH}"
  ok "Using Node: $(node --version)"
}

install_codex_cli() {
  [[ "${SKIP_CODEX_CLI}" == true ]] && return 0
  section "Codex CLI"
  install_nodejs
  if [[ "${DRY_RUN}" == true ]]; then
    info "Would install or update @openai/codex@latest"
    return 0
  fi
  run npm config set prefix "${LOCAL_BIN%/bin}"
  run npm install -g @openai/codex@latest
  if have codex; then
    ok "Using Codex CLI: $(codex --version)"
    if ! codex doctor >/dev/null 2>&1; then
      warn "codex doctor reported issues. Run 'codex doctor' after install; auth may require 'codex login'."
    fi
  else
    die "Codex CLI install finished but codex is not on PATH"
  fi
}

required_tools() {
  case "${PROFILE}" in
    fast)
      printf '%s\n' subfinder dnsx httpx katana
      ;;
    normal|deep|all)
      printf '%s\n' subfinder dnsx httpx katana gau waybackurls
      ;;
  esac
}

optional_tools() {
  case "${PROFILE}" in
    fast)
      printf '%s\n' nuclei
      ;;
    normal)
      printf '%s\n' naabu nuclei
      ;;
    deep|all)
      printf '%s\n' amass bbot uncover alterx tlsx waymore paramspider kiterunner gitleaks trufflehog arjun gf qsreplace kxss naabu nuclei
      ;;
  esac
}

go_package_for() {
  case "$1" in
    subfinder) echo "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
    dnsx) echo "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" ;;
    httpx) echo "github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
    katana) echo "github.com/projectdiscovery/katana/cmd/katana@latest" ;;
    gau) echo "github.com/lc/gau/v2/cmd/gau@latest" ;;
    waybackurls) echo "github.com/tomnomnom/waybackurls@latest" ;;
    naabu) echo "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" ;;
    nuclei) echo "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
    uncover) echo "github.com/projectdiscovery/uncover/cmd/uncover@latest" ;;
    alterx) echo "github.com/projectdiscovery/alterx/cmd/alterx@latest" ;;
    tlsx) echo "github.com/projectdiscovery/tlsx/cmd/tlsx@latest" ;;
    gf) echo "github.com/tomnomnom/gf@latest" ;;
    qsreplace) echo "github.com/tomnomnom/qsreplace@latest" ;;
    kxss) echo "github.com/Emoe/kxss@latest" ;;
    gitleaks) echo "github.com/gitleaks/gitleaks/v8@latest" ;;
    trufflehog) echo "github.com/trufflesecurity/trufflehog/v3@latest" ;;
    *) return 1 ;;
  esac
}

pipx_package_for() {
  case "$1" in
    bbot) echo "bbot" ;;
    waymore) echo "waymore" ;;
    paramspider) echo "git+https://github.com/devanshbatham/ParamSpider.git" ;;
    arjun) echo "arjun" ;;
    *) return 1 ;;
  esac
}

binary_for() {
  case "$1" in
    kiterunner) echo "kr" ;;
    *) echo "$1" ;;
  esac
}

release_repo_for() {
  case "$1" in
    amass) echo "owasp-amass/amass" ;;
    kiterunner) echo "assetnote/kiterunner" ;;
    gitleaks) echo "gitleaks/gitleaks" ;;
    trufflehog) echo "trufflesecurity/trufflehog" ;;
    *) return 1 ;;
  esac
}

release_pattern_for() {
  case "$1" in
    amass) echo "linux.*amd64.*\\.(zip|tar\\.gz)$|linux.*x86_64.*\\.(zip|tar\\.gz)$" ;;
    kiterunner) echo "linux.*amd64.*\\.(zip|tar\\.gz)$|linux.*x86_64.*\\.(zip|tar\\.gz)$" ;;
    gitleaks) echo "linux.*x64.*\\.(zip|tar\\.gz)$|linux.*amd64.*\\.(zip|tar\\.gz)$|linux.*x86_64.*\\.(zip|tar\\.gz)$" ;;
    trufflehog) echo "linux.*amd64.*\\.(zip|tar\\.gz)$|linux.*x86_64.*\\.(zip|tar\\.gz)$" ;;
    *) return 1 ;;
  esac
}

install_go_tool() {
  local tool="$1"
  local pkg
  pkg="$(go_package_for "${tool}")" || return 1
  install_go
  info "Installing ${tool}: go install ${pkg}"
  run timeout "${TOOL_INSTALL_TIMEOUT}" go install "${pkg}"
}

install_pipx_tool() {
  local tool="$1"
  local pkg
  pkg="$(pipx_package_for "${tool}")" || return 1
  ensure_pipx
  info "Installing ${tool}: pipx install ${pkg}"
  run timeout "${TOOL_INSTALL_TIMEOUT}" pipx install --force "${pkg}"
}

install_release_tool() {
  local tool="$1"
  local repo pattern binary tmp api asset_url asset_file
  repo="$(release_repo_for "${tool}")" || return 1
  pattern="$(release_pattern_for "${tool}")" || return 1
  binary="$(binary_for "${tool}")"
  tmp="$(mktemp -d)"
  api="${tmp}/release.json"
  info "Resolving latest ${tool} release from ${repo}"
  run curl -fsSL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" \
    -o "${api}" "https://api.github.com/repos/${repo}/releases/latest"
  asset_url="$(
    python3 - "${api}" "${pattern}" <<'PY'
import json
import re
import sys

path, pattern = sys.argv[1], sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
rx = re.compile(pattern, re.I)
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if rx.search(name):
        print(asset["browser_download_url"])
        break
else:
    raise SystemExit(1)
PY
  )"
  asset_file="${tmp}/${asset_url##*/}"
  info "Downloading ${asset_url}"
  run curl -fL --retry 5 --connect-timeout 20 --max-time "${HTTP_TIMEOUT}" -o "${asset_file}" "${asset_url}"
  case "${asset_file}" in
    *.zip)
      run unzip -oq "${asset_file}" -d "${tmp}/extract"
      ;;
    *.tar.gz|*.tgz)
      ensure_dir "${tmp}/extract"
      run tar -xzf "${asset_file}" -C "${tmp}/extract"
      ;;
    *)
      return 1
      ;;
  esac
  ensure_dir "${TOOLS_BIN}"
  local found
  found="$(find "${tmp}/extract" -type f -name "${binary}" -perm /111 2>/dev/null | head -n 1 || true)"
  if [[ -z "${found}" ]]; then
    found="$(find "${tmp}/extract" -type f -name "${binary}" 2>/dev/null | head -n 1 || true)"
  fi
  [[ -n "${found}" ]] || die "Could not find ${binary} in ${tool} release archive"
  run install -m 0755 "${found}" "${TOOLS_BIN}/${binary}"
  run rm -rf "${tmp}"
}

install_tool() {
  local tool="$1"
  local required="$2"
  local binary
  binary="$(binary_for "${tool}")"
  if have "${binary}"; then
    ok "${tool} already available at $(command -v "${binary}")"
    return 0
  fi

  if [[ "${DRY_RUN}" == true ]]; then
    if go_package_for "${tool}" >/dev/null 2>&1; then
      info "Would install ${tool} with go install $(go_package_for "${tool}")"
    elif pipx_package_for "${tool}" >/dev/null 2>&1; then
      info "Would install ${tool} with pipx install $(pipx_package_for "${tool}")"
    elif release_repo_for "${tool}" >/dev/null 2>&1; then
      info "Would install ${tool} from GitHub release $(release_repo_for "${tool}")"
    else
      warn "No installer route for ${tool}"
    fi
    return 0
  fi

  if go_package_for "${tool}" >/dev/null 2>&1 && install_go_tool "${tool}"; then
    return 0
  fi
  if pipx_package_for "${tool}" >/dev/null 2>&1 && install_pipx_tool "${tool}"; then
    return 0
  fi
  if release_repo_for "${tool}" >/dev/null 2>&1 && install_release_tool "${tool}"; then
    return 0
  fi

  if [[ "${required}" == true ]]; then
    die "Failed to install required tool: ${tool}"
  fi
  warn "Failed to install optional tool: ${tool}"
  return 0
}

install_tools() {
  section "DONZO recon tools"
  ensure_dir "${TOOLS_BIN}"
  ensure_dir "${GO_BIN}"
  ensure_dir "${LOCAL_BIN}"

  local tool
  while IFS= read -r tool; do
    [[ -n "${tool}" ]] || continue
    install_tool "${tool}" true
  done < <(required_tools)

  [[ "${REQUIRED_ONLY}" == true ]] && return 0

  while IFS= read -r tool; do
    [[ -n "${tool}" ]] || continue
    install_tool "${tool}" false
  done < <(optional_tools)
}

run_preflight() {
  [[ "${DRY_RUN}" == true ]] && return 0
  section "DONZO tool preflight"
  local py="${python_bin:-}"
  if [[ -z "${py}" ]]; then
    if [[ -x "${VENV_DIR}/bin/python" ]]; then
      py="${VENV_DIR}/bin/python"
    elif have python3.11; then
      py="python3.11"
    else
      py="python3"
    fi
  fi
  cd "${REPO_ROOT}"
  if "${py}" -m donzo tools check --profile "${PROFILE/all/deep}"; then
    ok "DONZO tool preflight passed"
  else
    die "DONZO tool preflight failed"
  fi
}

main() {
  section "DONZO WSL installer"
  info "Repo: ${REPO_ROOT}"
  info "Profile: ${PROFILE}"
  append_profile_path
  install_base_packages
  install_python_deps
  install_codex_cli
  install_tools
  run_preflight
  ok "Done. Open a new WSL shell or run: source ~/.profile"
}

main "$@"
