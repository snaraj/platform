#!/usr/bin/env bash
# Shared helpers for bootstrap/pi/hardening. Sourced, never executed.
# shellcheck disable=SC2034 # variables are consumed by the sourcing scripts.
# Every script here is root-only, idempotent, and keeps a backup of what it
# replaces so --revert is a restore, not a guess.

hardening_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
env_file=/etc/platform-hardening/hardening.env
state_root=/var/backups/platform-hardening
# One backup directory per component per invocation; revert uses the newest
# backup OF THAT COMPONENT, never another component's.
backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir=''
set_component() { backup_dir="${state_root}/$1/${backup_stamp}"; }

require_root() { [[ "${EUID}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 2; }; }

load_env() {
  # The env file is optional for components that need no host-specific input.
  UPLINK_INTERFACE=''; EGRESS_VPN_INTERFACE=''; EGRESS_VPN_PORT=''
  STALE_MOUNT_UNIT=''; STALE_MOUNT_ROOT=''; ORPHAN_WG_INTERFACE=''; ORPHAN_WG_PORT=''
  ADMIN_TARGET_FILE=''; CLUSTER_CIDRS=''; LOGIN_UID_MIN=1000; LOGIN_UID_MAX=59999
  if [[ -f "${env_file}" ]]; then
    [[ "$(stat -c '%U:%a' "${env_file}")" == root:600 ]] || { printf 'env file must be root:600\n' >&2; exit 2; }
    # shellcheck disable=SC1090 # root-owned 0600 file, validated above.
    source "${env_file}"
  fi
  for v in UPLINK_INTERFACE EGRESS_VPN_INTERFACE ORPHAN_WG_INTERFACE; do
    [[ -z "${!v}" || "${!v}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { printf '%s is not an interface name\n' "$v" >&2; exit 2; }
  done
  for c in ${CLUSTER_CIDRS}; do
    [[ "$c" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || { printf 'CLUSTER_CIDRS entry is not an IPv4 CIDR\n' >&2; exit 2; }
  done
  [[ "${LOGIN_UID_MIN}" =~ ^[0-9]+$ && "${LOGIN_UID_MAX}" =~ ^[0-9]+$ ]] || { printf 'LOGIN_UID_* must be numeric\n' >&2; exit 2; }
  for v in EGRESS_VPN_PORT ORPHAN_WG_PORT; do
    [[ -z "${!v}" || "${!v}" =~ ^[0-9]{1,5}$ ]] || { printf '%s is not a port\n' "$v" >&2; exit 2; }
  done
}

say() { printf '%s\n' "$*"; }
result() { printf 'HARDENING_%s=%s\n' "$1" "$2"; }

# backup_path FILE: copy FILE (if present) under the backup dir, mirroring its path.
backup_path() {
  local f="$1"
  install -d -m 0700 "${backup_dir}"
  if [[ -e "$f" ]]; then
    install -d -m 0700 "${backup_dir}$(dirname "$f")"
    cp -a "$f" "${backup_dir}${f}"
  else
    install -d -m 0700 "${backup_dir}$(dirname "$f")"
    : > "${backup_dir}${f}.absent"
  fi
}

# install_file SRC DST MODE: back up DST, then install SRC there.
install_file() {
  local src="$1" dst="$2" mode="$3"
  backup_path "$dst"
  install -D -m "$mode" "$src" "$dst"
}

# restore_path FILE FROM: put FILE back as it was in backup dir FROM. Returns
# non-zero when the backup holds nothing about FILE, so a caller never
# reports a restore that did not happen. Content and mode are restored; the
# owner is left to the target filesystem (the boot partition is vfat).
restore_path() {
  local f="$1" from="$2"
  if [[ -e "${from}${f}.absent" ]]; then rm -f "$f"; return 0; fi
  [[ -e "${from}${f}" ]] || return 1
  cp "${from}${f}" "$f" || return 1
  chmod --reference="${from}${f}" "$f" 2>/dev/null || true
}

# latest_backup COMPONENT: newest backup directory of that component, or empty.
latest_backup() { find "${state_root}/$1" -mindepth 1 -maxdepth 1 -type d -name '*Z' 2>/dev/null | sort | tail -1; }

# arm_revert NAME SECONDS COMMAND...: schedule an automatic revert; disarm_revert cancels it.
arm_revert() {
  local name="$1" secs="$2"; shift 2
  systemctl stop "platform-revert-${name}.timer" 2>/dev/null || true
  systemd-run --quiet --on-active="${secs}" --unit="platform-revert-${name}" --description="auto-revert ${name}" "$@"
}
disarm_revert() { systemctl stop "platform-revert-$1.timer" 2>/dev/null || true; }
