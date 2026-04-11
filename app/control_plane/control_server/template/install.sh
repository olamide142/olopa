#!/usr/bin/env sh
# Olopa Agent Installer
# Usage: curl -fLs https://olopa.io/install.sh | sudo sh
# Usage: curl -fLs https://olopa.io/install.sh | OLOPA_TOKEN=<token> sudo -E sh
#
# Environment variables:
#   OLOPA_TOKEN        - Enrollment token (required for managed install)
#   OLOPA_VERSION      - Pin a specific version (default: latest)
#   OLOPA_INSTALL_DIR  - Override install prefix (default: /usr/local)
#   OLOPA_NO_SERVICE   - Set to 1 to skip systemd service installation
#   OLOPA_BACKEND_URL  - Override backend URL (default: ingest.olopa.io:4317)
#   OLOPA_RELEASES_URL - Override releases base URL (default: https://releases.olopa.io/olopa)
#   OLOPA_RELEASES_FALLBACK_URL - Optional fallback releases URL

set -eu

# --- Formatting --------------------------------------------------------------

BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

print_banner() {
    printf "\n"
    printf "${BOLD}${CYAN}"
    printf "  /******  /**                              \n"
    printf " /**__  **| **                              \n"
    printf "| **  \ **| **  /******   /******   /****** \n"
    printf "| **  | **| ** /**__  ** /**__  ** |____  **\n"
    printf "| **  | **| **| **  \ **| **  \ **  /*******\n"
    printf "| **  | **| **| **  | **| **  | ** /**__  **\n"
    printf "|  ******/| **|  ******/| *******/|  *******\n"
    printf " \______/ |__/ \______/ | **____/  \_______/\n"
    printf "                        | **\n"
    printf "                        | **\n"
    printf "                        |__/\n"
    printf '%s\n' "--------------------------------------v0.0.1----"
    printf "${RESET}"
    printf "  ${DIM}kernel-native security agent${RESET}\n\n"
}

info()    { printf "  ${CYAN}→${RESET}  %s\n" "$1"; }
success() { printf "  ${GREEN}✓${RESET}  %s\n" "$1"; }
warn()    { printf "  ${YELLOW}!${RESET}  %s\n" "$1"; }
die()     { printf "\n  ${RED}✗${RESET}  ${BOLD}%s${RESET}\n\n" "$1" >&2; exit 1; }
step()    { printf "\n  ${BOLD}%s${RESET}\n" "$1"; }

# --- Configuration ------------------------------------------------------------

OLOPA_VERSION="${OLOPA_VERSION:-latest}"
OLOPA_INSTALL_DIR="${OLOPA_INSTALL_DIR:-/usr/local}"
OLOPA_BACKEND_URL="${OLOPA_BACKEND_URL:-ingest.olopa.io:4317}"
OLOPA_NO_SERVICE="${OLOPA_NO_SERVICE:-0}"
OLOPA_TOKEN="${OLOPA_TOKEN:-}"
OLOPA_RELEASES_URL="${OLOPA_RELEASES_URL:-https://releases.olopa.io/olopa}"
OLOPA_RELEASES_FALLBACK_URL="${OLOPA_RELEASES_FALLBACK_URL:-https://olopa.t3.tigrisfiles.io/olopa}"

BINARY_NAME="olopa-agent"
BINARY_DIR="${OLOPA_INSTALL_DIR}/bin"
CONFIG_DIR="/etc/olopa"
DATA_DIR="/var/lib/olopa"
LOG_DIR="/var/log/olopa"
SERVICE_FILE="/etc/systemd/system/olopa-agent.service"
RELEASES_URL="${OLOPA_RELEASES_URL%/}"
RELEASES_FALLBACK_URL="${OLOPA_RELEASES_FALLBACK_URL%/}"
DOWNLOADED_AGENT_PATH=""

# --- Pre-flight checks --------------------------------------------------------

check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "This installer must be run as root. Try: curl -fLs https://olopa.io/install.sh | sudo sh"
  fi
}

check_os() {
  case "$(uname -s)" in
    Linux) : ;;
    Darwin) warn "macOS detected — eBPF probes require Linux. Sensor layer will be disabled." ;;
    *) die "Unsupported OS: $(uname -s). Olopa requires Linux ≥ 5.4." ;;
  esac
}

check_kernel() {
  if [ "$(uname -s)" = "Linux" ]; then
    KERNEL_VERSION="$(uname -r | cut -d. -f1-2)"
    KERNEL_MAJOR="$(echo "$KERNEL_VERSION" | cut -d. -f1)"
    KERNEL_MINOR="$(echo "$KERNEL_VERSION" | cut -d. -f2)"

    if [ "$KERNEL_MAJOR" -lt 5 ]; then
      die "Kernel $(uname -r) is too old. Olopa requires Linux ≥ 5.4 (for eBPF ring buffers)."
    fi
    if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]; then
      die "Kernel $(uname -r) is too old. Olopa requires Linux ≥ 5.4."
    fi
    if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]; then
      warn "Kernel $(uname -r): ring buffers unavailable (< 5.8), falling back to perf buffers."
    fi
    success "Kernel $(uname -r) — eBPF supported"
  fi
}

check_arch() {
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)  ARCH_TAG="x86_64" ;;
    aarch64) ARCH_TAG="aarch64" ;;
    arm64)   ARCH_TAG="aarch64" ;;
    *)       die "Unsupported architecture: $ARCH. Olopa supports x86_64 and aarch64." ;;
  esac
  success "Architecture: $ARCH_TAG"
}

check_deps() {
  for cmd in curl sha256sum; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      die "Required tool not found: $cmd. Please install it and re-run."
    fi
  done

  # systemd check (soft)
  if [ "$OLOPA_NO_SERVICE" = "0" ] && ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd not found — skipping service installation. Set OLOPA_NO_SERVICE=1 to suppress this."
    OLOPA_NO_SERVICE=1
  fi
}

# --- Version resolution -------------------------------------------------------

try_resolve_latest_from() {
  BASE_URL="$1"
  CANDIDATE_VERSION="$(curl -fsSL "${BASE_URL}/latest/version" 2>/dev/null || true)"
  CANDIDATE_VERSION="$(echo "$CANDIDATE_VERSION" | tr -d '[:space:]')"
  if [ -z "$CANDIDATE_VERSION" ]; then
    return 1
  fi
  OLOPA_VERSION="$CANDIDATE_VERSION"
  RELEASES_URL="$BASE_URL"
  return 0
}

resolve_version() {
  if [ "$OLOPA_VERSION" = "latest" ]; then
    info "Resolving latest release..."
    if try_resolve_latest_from "$RELEASES_URL"; then
      :
    elif [ -n "$RELEASES_FALLBACK_URL" ] \
      && [ "$RELEASES_FALLBACK_URL" != "$RELEASES_URL" ] \
      && try_resolve_latest_from "$RELEASES_FALLBACK_URL"; then
      warn "Primary releases endpoint unavailable; using fallback ${RELEASES_URL}"
    else
      die "Failed to fetch latest version from ${RELEASES_URL} (and fallback). Check DNS/network or set OLOPA_RELEASES_URL."
    fi
  fi
  success "Version: ${OLOPA_VERSION}"
  info "Release endpoint: ${RELEASES_URL}"
}

# --- Download + verify --------------------------------------------------------

download_agent() {
  DOWNLOAD_URL="${RELEASES_URL}/${OLOPA_VERSION}/${BINARY_NAME}-${OLOPA_VERSION}-${ARCH_TAG}-linux-musl"
  CHECKSUM_URL="${RELEASES_URL}/${OLOPA_VERSION}/checksums.txt"

  TMPDIR="$(mktemp -d)"
  TMPBIN="${TMPDIR}/${BINARY_NAME}"
  TMPSUMS="${TMPDIR}/checksums.txt"

  info "Downloading agent binary..."
  curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$TMPBIN" \
    || die "Download failed: ${DOWNLOAD_URL}"

  info "Downloading checksums..."
  curl -fsSL "$CHECKSUM_URL" -o "$TMPSUMS" \
    || die "Checksum download failed: ${CHECKSUM_URL}"

  info "Verifying integrity..."
  EXPECTED_SUM="$(grep "${BINARY_NAME}-${OLOPA_VERSION}-${ARCH_TAG}-linux-musl" "$TMPSUMS" | awk '{print $1}')"
  [ -n "$EXPECTED_SUM" ] || die "No checksum entry found for this binary in checksums.txt"

  ACTUAL_SUM="$(sha256sum "$TMPBIN" | awk '{print $1}')"
  [ "$EXPECTED_SUM" = "$ACTUAL_SUM" ] || die "Checksum mismatch"

  chmod 755 "$TMPBIN"
  DOWNLOADED_AGENT_PATH="$TMPBIN"
  success "Checksum verified"
}

# --- Install ------------------------------------------------------------------

install_binary() {
  TMPBIN="$1"
  mkdir -p "$BINARY_DIR"
  mv "$TMPBIN" "${BINARY_DIR}/${BINARY_NAME}"
  success "Binary installed → ${BINARY_DIR}/${BINARY_NAME}"
}

install_config() {
  mkdir -p "$CONFIG_DIR"
  mkdir -p "$DATA_DIR"
  mkdir -p "$LOG_DIR"

  # Don't overwrite existing config
  if [ -f "${CONFIG_DIR}/config.toml" ]; then
    warn "Config already exists at ${CONFIG_DIR}/config.toml — skipping. Edit manually to update."
    return
  fi

  HOST_ID="$(hostname -f 2>/dev/null || hostname)"
  TENANT_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "unknown")"

  cat > "${CONFIG_DIR}/config.toml" <<EOF
# Olopa Agent Configuration
# Generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Full reference: https://docs.olopa.io/agent/config

[agent]
version        = "${OLOPA_VERSION}"
host_id        = "${HOST_ID}"
# tenant_id is set from your enrollment token — do not edit
# tenant_id = ""

[backend]
url            = "${OLOPA_BACKEND_URL}"
# tls_cert_path = "/etc/olopa/agent.crt"
# tls_key_path  = "/etc/olopa/agent.key"
# tls_ca_path   = "/etc/olopa/ca.crt"

[enrollment]
# Paste your enrollment token here, or set via OLOPA_TOKEN env var
# token = ""

[ebpf]
# Probes to enable. Comment out to disable individual sensors.
probes = ["exec", "file", "network"]
# xdp_iface = "eth0"   # enable XDP fast-path on this interface

[scheduler]
# MDKP telemetry scheduler budgets
cpu_budget_pct  = 5.0
mem_budget_mb   = 50
net_budget_kbps = 5120   # 5 MB/s

[compression]
# zstd compression level: 1 (fast) → 9 (max)
level = 3

[logging]
level   = "info"
file    = "${LOG_DIR}/agent.log"
max_mb  = 100
EOF

  # Inject token if provided at install time
  if [ -n "$OLOPA_TOKEN" ]; then
    sed -i "s|# token = \"\"|token = \"${OLOPA_TOKEN}\"|" "${CONFIG_DIR}/config.toml"
    success "Enrollment token written to config"
  else
    warn "No OLOPA_TOKEN set — edit ${CONFIG_DIR}/config.toml to add your token before starting."
  fi

  chmod 640 "${CONFIG_DIR}/config.toml"
  success "Config written → ${CONFIG_DIR}/config.toml"
}

install_service() {
  if [ "$OLOPA_NO_SERVICE" = "1" ]; then
    warn "Skipping systemd service installation (OLOPA_NO_SERVICE=1)"
    return
  fi

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Olopa Security Agent
Documentation=https://docs.olopa.io
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${BINARY_DIR}/${BINARY_NAME} --config ${CONFIG_DIR}/config.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Run as root — required for CAP_BPF
User=root
Group=root

# Resource limits
Nice=10
IOSchedulingClass=idle
CPUWeight=10
MemoryMax=150M

# Minimum required capabilities — no CAP_SYS_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_RAW
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_RAW
NoNewPrivileges=true

# Filesystem hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR} ${CONFIG_DIR}

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable olopa-agent >/dev/null 2>&1
  success "systemd service installed and enabled"
}

start_service() {
  if [ "$OLOPA_NO_SERVICE" = "1" ]; then
    return
  fi

  # Only auto-start if a token is configured
  if [ -n "$OLOPA_TOKEN" ]; then
    systemctl start olopa-agent
    sleep 1
    if systemctl is-active --quiet olopa-agent; then
      success "Agent started (olopa-agent.service)"
    else
      warn "Agent failed to start — check logs: journalctl -u olopa-agent -n 50"
    fi
  else
    warn "Agent not started — add enrollment token to ${CONFIG_DIR}/config.toml, then run:"
    printf "       ${DIM}sudo systemctl start olopa-agent${RESET}\n"
  fi
}

# --- Post-install summary -----------------------------------------------------

print_summary() {
  printf "\n"
  printf "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
  printf "\n"
  printf "  ${GREEN}${BOLD}Olopa Agent ${OLOPA_VERSION} installed successfully.${RESET}\n"
  printf "\n"
  printf "  ${DIM}Binary  ${RESET}  ${BINARY_DIR}/${BINARY_NAME}\n"
  printf "  ${DIM}Config  ${RESET}  ${CONFIG_DIR}/config.toml\n"
  printf "  ${DIM}Logs    ${RESET}  ${LOG_DIR}/agent.log\n"
  printf "\n"

  if [ -z "$OLOPA_TOKEN" ]; then
    printf "  ${YELLOW}${BOLD}Next step:${RESET} add your enrollment token\n"
    printf "\n"
    printf "  ${DIM}1. Edit config:${RESET}\n"
    printf "     sudo nano ${CONFIG_DIR}/config.toml\n"
    printf "\n"
    printf "  ${DIM}2. Set the token under [enrollment]:${RESET}\n"
    printf "     token = \"<your-token>\"\n"
    printf "\n"
    printf "  ${DIM}3. Start the agent:${RESET}\n"
    printf "     sudo systemctl start olopa-agent\n"
  else
    printf "  ${DIM}Service status:${RESET}\n"
    printf "     systemctl status olopa-agent\n"
    printf "     journalctl -u olopa-agent -f\n"
  fi

  printf "\n"
  printf "  ${DIM}Docs:${RESET} https://docs.olopa.io/quickstart\n"
  printf "\n"
  printf "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
  printf "\n"
}

# --- Main ---------------------------------------------------------------------

main() {
  print_banner

  step "Pre-flight checks"
  check_root
  check_os
  check_kernel
  check_arch
  check_deps

  step "Resolving version"
  resolve_version

  step "Downloading agent"
  download_agent
  TMPBIN="${DOWNLOADED_AGENT_PATH}"
  [ -n "$TMPBIN" ] || die "Download failed unexpectedly: no binary path returned."

  step "Installing"
  install_binary "$TMPBIN"
  install_config
  install_service

  step "Starting agent"
  start_service

  print_summary
}

main
