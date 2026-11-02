#!/usr/bin/env bash
# apply-hardening.sh — install one hardening component, verify it, or put it back.
#
# Usage: sudo apply-hardening.sh <plan|apply|revert> <component>
# Components: sysctl units journald auditd apt needrestart debsums egress
#             sshd-listen cmdline ipv6 cluster-files
#
# Each apply backs up what it touches, applies, then runs verify-hardening.sh
# for that component. Components that can lock an operator out (egress,
# sshd-listen) are armed with a 10-minute automatic revert that is cancelled
# only when the verifier passes. cmdline is staged: it edits the boot command
# line and takes effect on the owner's next reboot, never before.
set -Eeuo pipefail
# shellcheck source=bootstrap/pi/hardening/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
require_root; load_env
action="${1:-}"; comp="${2:-}"
verify="${hardening_root}/verify-hardening.sh"
sysctl_dst=/etc/sysctl.d/99-zz-platform-kernel-hardening.conf
cmdline=/boot/firmware/cmdline.txt
egress_dst=/etc/platform-hardening/egress-allowlist.nft
listen_dst=/etc/systemd/system/ssh.socket.d/70-platform-listen.conf

units=(cloudflared ntpsec containerd kubelet)

render_egress() {
  local transport=''
  if [[ -n "${EGRESS_VPN_INTERFACE}" && -n "${EGRESS_VPN_PORT}" && -n "${UPLINK_INTERFACE}" ]]; then
    transport="oifname \"${UPLINK_INTERFACE}\" udp dport ${EGRESS_VPN_PORT} accept"
  fi
  local cidrs='' c
  for c in ${CLUSTER_CIDRS}; do cidrs="${cidrs}ip daddr ${c} accept
    "; done
  sed -e "s|@VPN_TRANSPORT@|${transport}|" -e "s|@LOGIN_UIDS@|${LOGIN_UID_MIN}-${LOGIN_UID_MAX}|" \
      -e "s|@CLUSTER_CIDRS@|${cidrs%$'\n'    }|" "${hardening_root}/nftables/egress-allowlist.nft.template"
}

admin_target() {
  [[ -n "${ADMIN_TARGET_FILE}" && -f "${ADMIN_TARGET_FILE}" ]] || return 1
  local line; line="$(sed -n '1p' "${ADMIN_TARGET_FILE}")"
  [[ "${line}" =~ ^TARGET=(([0-9]{1,3}\.){3}[0-9]{1,3})/32$ ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

plan() {
  case "$comp" in
    sysctl)   say "install ${sysctl_dst}; sysctl --system" ;;
    units)    say "install 70-platform-sandbox.conf drop-ins for: ${units[*]}; daemon-reload; restart each in turn with a health check" ;;
    journald) say "install journald 70-platform-seal.conf; restart journald; generate FSS keys (verification key to the operator only)" ;;
    auditd)   say "install auditd rules; enable auditd" ;;
    apt)      say "install unattended-upgrades security-only policy" ;;
    needrestart) say "install needrestart policy" ;;
    debsums)  say "install daily debsums timer" ;;
    egress)   say "render and load table inet platform_egress with a 10-minute revert, verify, persist as a unit"; render_egress ;;
    sshd-listen) say "render ssh.socket listeners from the admin target with a 10-minute revert" ;;
    cmdline)  say "append to ${cmdline}: $(<"${hardening_root}/cmdline/platform-kernel-hardening.cmdline") (effective after the owner's reboot)" ;;
    ipv6)     say "set ipv6.method disabled on the uplink connection and re-apply it" ;;
    cluster-files) say "tighten modes: /var/lib/etcd 0700; kubelet unit and drop-ins 0600 (CIS 1.1.11, 4.1.1, 4.1.2)" ;;
    *) printf 'unknown component\n' >&2; exit 2 ;;
  esac
}

apply() {
  case "$comp" in
    sysctl)
      install_file "${hardening_root}/sysctl/99-zz-platform-kernel-hardening.conf" "${sysctl_dst}" 0644
      sysctl --system >/dev/null ;;
    units)
      for u in "${units[@]}"; do
        install_file "${hardening_root}/systemd/${u}.service.d/70-platform-sandbox.conf" "/etc/systemd/system/${u}.service.d/70-platform-sandbox.conf" 0644
      done
      systemctl daemon-reload
      for u in cloudflared ntpsec; do
        systemctl restart "${u}.service"; sleep 3
        systemctl is-active --quiet "${u}.service" || { say "unit ${u} failed after sandboxing; reverting it"; restore_path "/etc/systemd/system/${u}.service.d/70-platform-sandbox.conf" "${backup_dir}"; systemctl daemon-reload; systemctl restart "${u}.service"; result UNITS FAIL; exit 1; }
      done
      # containerd and kubelet pick the fences up on their next restart; a
      # live restart is the owner's call because it churns every pod.
      ;;
    journald)
      install_file "${hardening_root}/journald/70-platform-seal.conf" /etc/systemd/journald.conf.d/70-platform-seal.conf 0644
      systemctl restart systemd-journald
      if ! ls /var/log/journal/*/fss >/dev/null 2>&1; then
        say "FSS keys: run 'journalctl --setup-keys --interval=15min' in the operator's own session and keep its verification key off this host."
      fi ;;
    auditd)
      install_file "${hardening_root}/auditd/platform.rules" /etc/audit/rules.d/platform.rules 0640
      systemctl enable --now auditd
      augenrules --load >/dev/null 2>&1 || true ;;
    apt)
      install_file "${hardening_root}/apt/52-platform-unattended-security.conf" /etc/apt/apt.conf.d/52-platform-unattended-security.conf 0644
      unattended-upgrade --dry-run >/dev/null 2>&1 || true ;;
    needrestart)
      install_file "${hardening_root}/needrestart/platform.conf" /etc/needrestart/conf.d/platform.conf 0644 ;;
    debsums)
      install_file "${hardening_root}/systemd/platform-debsums.service" /etc/systemd/system/platform-debsums.service 0644
      install_file "${hardening_root}/systemd/platform-debsums.timer" /etc/systemd/system/platform-debsums.timer 0644
      systemctl daemon-reload; systemctl enable --now platform-debsums.timer ;;
    egress)
      install -d -m 0700 /etc/platform-hardening
      backup_path "${egress_dst}"; render_egress > "${egress_dst}"; chmod 0600 "${egress_dst}"
      nft -c -f "${egress_dst}"
      arm_revert egress 600 /usr/sbin/nft delete table inet platform_egress
      nft -f "${egress_dst}"
      if "${verify}" egress; then
        disarm_revert egress
        install_file "${hardening_root}/systemd/platform-egress-allowlist.service" /etc/systemd/system/platform-egress-allowlist.service 0644
        systemctl daemon-reload; systemctl enable platform-egress-allowlist.service >/dev/null 2>&1
      else
        nft delete table inet platform_egress; disarm_revert egress; result EGRESS FAIL; exit 1
      fi ;;
    sshd-listen)
      target="$(admin_target)" || { say "ADMIN_TARGET_FILE missing or malformed; nothing changed"; result SSHD_LISTEN SKIP; exit 0; }
      backup_path "${listen_dst}"
      install -d -m 0755 "$(dirname "${listen_dst}")"
      sed "s|@ADMIN_TARGET@|${target}|" "${hardening_root}/systemd/ssh.socket.d/70-platform-listen.conf.template" > "${listen_dst}"
      arm_revert sshd-listen 600 /bin/sh -c "rm -f ${listen_dst}; systemctl daemon-reload; systemctl restart ssh.socket"
      systemctl daemon-reload; systemctl restart ssh.socket
      if "${verify}" sshd-listen; then disarm_revert sshd-listen
      else rm -f "${listen_dst}"; systemctl daemon-reload; systemctl restart ssh.socket; disarm_revert sshd-listen; result SSHD_LISTEN FAIL; exit 1; fi ;;
    cmdline)
      backup_path "${cmdline}"
      local -a want; read -ra want < "${hardening_root}/cmdline/platform-kernel-hardening.cmdline"
      current="$(cat "${cmdline}")"
      for tok in "${want[@]}"; do
        key="${tok%%=*}"
        current="$(printf '%s' "${current}" | sed -E "s/(^| )${key}(=[^ ]*)?( |$)/\1/g")"
        current="${current% } ${tok}"
      done
      printf '%s\n' "${current}" | tr -s ' ' > "${cmdline}.new" && mv "${cmdline}.new" "${cmdline}"
      say "staged; effective after reboot" ;;
    ipv6)
      [[ -n "${UPLINK_INTERFACE}" ]] || { printf 'UPLINK_INTERFACE unset\n' >&2; exit 2; }
      con="$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="${UPLINK_INTERFACE}" '$2==d{print $1; exit}')"
      [[ -n "${con}" ]] || { printf 'no active connection on uplink\n' >&2; exit 2; }
      install -d -m 0700 "${backup_dir}"; nmcli -t -f ipv6.method con show "${con}" > "${backup_dir}/ipv6.method.previous"
      nmcli con modify "${con}" ipv6.method disabled
      nmcli con up "${con}" >/dev/null ;;
    cluster-files)
      install -d -m 0700 "${backup_dir}"; stat -c '%a %n' /var/lib/etcd /etc/systemd/system/kubelet.service /etc/systemd/system/kubelet.service.d/*.conf > "${backup_dir}/cluster-files.modes" 2>/dev/null || true
      chmod 0700 /var/lib/etcd
      chmod 0600 /etc/systemd/system/kubelet.service /etc/systemd/system/kubelet.service.d/*.conf ;;
    *) printf 'unknown component\n' >&2; exit 2 ;;
  esac
  "${verify}" "$comp"
}

revert() {
  from="$(latest_backup)"; [[ -n "${from}" ]] || { printf 'no backup to revert from\n' >&2; exit 2; }
  case "$comp" in
    sysctl)   restore_path "${sysctl_dst}" "${from}"; sysctl --system >/dev/null ;;
    units)    for u in "${units[@]}"; do restore_path "/etc/systemd/system/${u}.service.d/70-platform-sandbox.conf" "${from}"; done; systemctl daemon-reload; systemctl restart cloudflared.service ntpsec.service ;;
    journald) restore_path /etc/systemd/journald.conf.d/70-platform-seal.conf "${from}"; systemctl restart systemd-journald ;;
    auditd)   restore_path /etc/audit/rules.d/platform.rules "${from}"; augenrules --load >/dev/null 2>&1 || true ;;
    apt)      restore_path /etc/apt/apt.conf.d/52-platform-unattended-security.conf "${from}" ;;
    needrestart) restore_path /etc/needrestart/conf.d/platform.conf "${from}" ;;
    debsums)  systemctl disable --now platform-debsums.timer >/dev/null 2>&1 || true; restore_path /etc/systemd/system/platform-debsums.timer "${from}"; restore_path /etc/systemd/system/platform-debsums.service "${from}"; systemctl daemon-reload ;;
    egress)   systemctl disable --now platform-egress-allowlist.service >/dev/null 2>&1 || true; nft delete table inet platform_egress 2>/dev/null || true; restore_path "${egress_dst}" "${from}"; restore_path /etc/systemd/system/platform-egress-allowlist.service "${from}"; systemctl daemon-reload ;;
    sshd-listen) restore_path "${listen_dst}" "${from}"; systemctl daemon-reload; systemctl restart ssh.socket ;;
    cmdline)  restore_path "${cmdline}" "${from}" ;;
    cluster-files) while read -r mode path; do chmod "${mode}" "${path}"; done < "${from}/cluster-files.modes" ;;
    ipv6)     con="$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="${UPLINK_INTERFACE}" '$2==d{print $1; exit}')"; prev="$(sed 's/^ipv6.method://' "${from}/ipv6.method.previous" 2>/dev/null || echo auto)"; nmcli con modify "${con}" ipv6.method "${prev}"; nmcli con up "${con}" >/dev/null ;;
    *) printf 'unknown component\n' >&2; exit 2 ;;
  esac
  result "REVERT_${comp^^}" DONE
}

case "$action" in
  plan) plan ;; apply) apply ;; revert) revert ;;
  *) printf 'usage: %s <plan|apply|revert> <component>\n' "$0" >&2; exit 2 ;;
esac
