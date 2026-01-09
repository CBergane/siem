#!/usr/bin/env bash
set -euo pipefail

error() {
  echo "install-agent: $*" >&2
}

info() {
  echo "install-agent: $*"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    error "Run as root (use sudo)."
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    error "Missing required env var: $name"
    exit 1
  fi
}

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    error "Missing required command: $name"
    exit 1
  fi
}

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
  esac
  return 1
}

run_cmd() {
  if is_true "${FRC_DRY_RUN:-0}"; then
    info "DRY RUN: $*"
    return 0
  fi
  "$@"
}

backup_file() {
  local target="$1"
  local stamp
  stamp="$(date +%Y%m%d%H%M%S)"
  if [[ -f "$target" ]]; then
    run_cmd cp "$target" "${target}.bak.${stamp}"
  fi
}

install_with_backup() {
  local src="$1"
  local dest="$2"
  local mode="$3"

  if [[ ! -f "$src" ]]; then
    error "Missing source file: $src"
    return 1
  fi

  if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
    info "Unchanged: $dest"
    return 1
  fi

  backup_file "$dest"
  run_cmd install -m "$mode" "$src" "$dest"
  return 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="${SCRIPT_DIR}/agent"
ENV_FILE="/etc/frc-agent.env"

uninstall() {
  require_root
  systemctl disable --now frc-nginx.service frc-fail2ban.service frc-inventory.timer >/dev/null 2>&1 || true
  systemctl stop frc-inventory.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/frc-nginx.service
  rm -f /etc/systemd/system/frc-fail2ban.service
  rm -f /etc/systemd/system/frc-inventory.service
  rm -f /etc/systemd/system/frc-inventory.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f /usr/local/bin/frc-agent-nginx-tail
  rm -f /usr/local/bin/frc-agent-fail2ban-tail
  rm -f /usr/local/bin/frc-agent-inventory
  rm -f "$ENV_FILE"
  info "Uninstalled."
}

if [[ "${1:-}" == "--uninstall" ]]; then
  uninstall
  exit 0
fi

require_root
require_cmd systemctl
require_cmd curl
require_cmd openssl
require_cmd python3

require_env FRC_URL
require_env FRC_API_KEY
require_env FRC_AGENT_ID
require_env FRC_AGENT_SECRET

ENABLE_NGINX_AGENT="${ENABLE_NGINX_AGENT:-0}"
ENABLE_FAIL2BAN_AGENT="${ENABLE_FAIL2BAN_AGENT:-0}"
ENABLE_INVENTORY_AGENT="${ENABLE_INVENTORY_AGENT:-1}"

if ! id -u frc-agent >/dev/null 2>&1; then
  run_cmd useradd -r -s /usr/sbin/nologin frc-agent
fi

env_content=$(cat <<EOF
FRC_URL=${FRC_URL}
FRC_API_KEY=${FRC_API_KEY}
FRC_AGENT_ID=${FRC_AGENT_ID}
FRC_AGENT_SECRET=${FRC_AGENT_SECRET}
ENABLE_NGINX_AGENT=${ENABLE_NGINX_AGENT}
ENABLE_FAIL2BAN_AGENT=${ENABLE_FAIL2BAN_AGENT}
ENABLE_INVENTORY_AGENT=${ENABLE_INVENTORY_AGENT}
EOF
)

if is_true "${FRC_DRY_RUN:-0}"; then
  info "DRY RUN: would write ${ENV_FILE}"
else
  umask 077
  if [[ -f "$ENV_FILE" ]] && cmp -s <(printf '%s' "$env_content") "$ENV_FILE"; then
    info "Unchanged: $ENV_FILE"
  else
    backup_file "$ENV_FILE"
    printf '%s' "$env_content" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    info "Wrote $ENV_FILE"
  fi
fi

nginx_changed=0
fail2ban_changed=0
inventory_changed=0
inventory_timer_changed=0

install_with_backup "${AGENT_DIR}/frc-agent-nginx-tail" /usr/local/bin/frc-agent-nginx-tail 0755 && nginx_changed=1 || true
install_with_backup "${AGENT_DIR}/frc-agent-fail2ban-tail" /usr/local/bin/frc-agent-fail2ban-tail 0755 && fail2ban_changed=1 || true
install_with_backup "${AGENT_DIR}/frc-agent-inventory" /usr/local/bin/frc-agent-inventory 0755 && inventory_changed=1 || true

install_with_backup "${AGENT_DIR}/frc-nginx.service" /etc/systemd/system/frc-nginx.service 0644 && nginx_changed=1 || true
install_with_backup "${AGENT_DIR}/frc-fail2ban.service" /etc/systemd/system/frc-fail2ban.service 0644 && fail2ban_changed=1 || true
install_with_backup "${AGENT_DIR}/frc-inventory.service" /etc/systemd/system/frc-inventory.service 0644 && inventory_changed=1 || true
install_with_backup "${AGENT_DIR}/frc-inventory.timer" /etc/systemd/system/frc-inventory.timer 0644 && inventory_timer_changed=1 || true

run_cmd systemctl daemon-reload

if is_true "$ENABLE_NGINX_AGENT"; then
  run_cmd systemctl enable --now frc-nginx.service
  info "Enabled frc-nginx.service"
  if [[ "$nginx_changed" -eq 1 ]]; then
    run_cmd systemctl try-restart frc-nginx.service || true
  fi
else
  info "Skipping frc-nginx.service (ENABLE_NGINX_AGENT=${ENABLE_NGINX_AGENT})"
fi

if is_true "$ENABLE_FAIL2BAN_AGENT"; then
  run_cmd systemctl enable --now frc-fail2ban.service
  info "Enabled frc-fail2ban.service"
  if [[ "$fail2ban_changed" -eq 1 ]]; then
    run_cmd systemctl try-restart frc-fail2ban.service || true
  fi
else
  info "Skipping frc-fail2ban.service (ENABLE_FAIL2BAN_AGENT=${ENABLE_FAIL2BAN_AGENT})"
fi

if is_true "$ENABLE_INVENTORY_AGENT"; then
  run_cmd systemctl enable --now frc-inventory.timer
  info "Enabled frc-inventory.timer"
  if [[ "$inventory_changed" -eq 1 || "$inventory_timer_changed" -eq 1 ]]; then
    run_cmd systemctl try-restart frc-inventory.timer || true
  fi
else
  info "Skipping frc-inventory.timer (ENABLE_INVENTORY_AGENT=${ENABLE_INVENTORY_AGENT})"
fi

info "Install complete."
