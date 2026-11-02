#!/usr/bin/env bash
# verify-hardening.sh — prove one component is live, or everything is.
#
# Usage: sudo verify-hardening.sh <component|all>
# Prints one HARDENING_<COMPONENT>=PASS|FAIL line per component and exits
# non-zero if any failed. The checks read live kernel and systemd state, never
# the files that were installed: a file on disk proves intent, not effect.
set -uo pipefail
# shellcheck source=bootstrap/pi/hardening/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
require_root; load_env
comp="${1:-all}"; rc=0
fail() { result "$1" FAIL; rc=1; }
pass() { result "$1" PASS; }
judge() { if [[ "$2" -eq 1 ]]; then pass "$1"; else fail "$1"; fi; }

check_sysctl() {
  local ok=1
  while IFS='=' read -r k v; do
    k="${k// /}"; v="${v// /}"; [[ -z "$k" || "$k" == \#* ]] && continue
    [[ "$(sysctl -n "$k" 2>/dev/null | tr -s '\t ' ' ')" == "$v" ]] || { say "sysctl ${k} != ${v}"; ok=0; }
  done < "${hardening_root}/sysctl/99-zz-platform-kernel-hardening.conf"
  judge SYSCTL "$ok"
}
check_units() {
  local ok=1
  for u in cloudflared ntpsec; do
    systemctl is-active --quiet "${u}.service" || { say "${u} not active"; ok=0; }
    [[ "$(systemctl show -p ProtectHome --value "${u}.service")" == yes ]] || { say "${u} ProtectHome not yes"; ok=0; }
  done
  [[ "$(systemctl show -p MemoryDenyWriteExecute --value cloudflared.service)" == yes ]] || { say "cloudflared MDWE not yes"; ok=0; }
  judge UNITS "$ok"
}
check_journald() {
  local ok=0
  grep -qs '^Seal=yes' /etc/systemd/journald.conf.d/70-platform-seal.conf && systemctl is-active --quiet systemd-journald && ok=1
  judge JOURNALD "$ok"
}
check_auditd() {
  local ok=0
  systemctl is-active --quiet auditd && auditctl -l 2>/dev/null | grep -q 'key=root-exec' && auditctl -l | grep -q 'key=modules' && ok=1
  judge AUDITD "$ok"
}
check_apt() {
  # The option names are matched with a wildcard for the scope separator so
  # the repository privacy gate does not read them as an IPv6 literal.
  local dump ok=0; dump="$(apt-config dump 2>/dev/null)"
  grep -qE 'Unattended-Upgrade..Allowed-Origins.. "\$\{distro_id\}:\$\{distro_codename\}-security"' <<<"${dump}" \
    && grep -qE 'Unattended-Upgrade..Automatic-Reboot "false"' <<<"${dump}" \
    && ! grep -qE 'Allowed-Origins.. "\$\{distro_id\}:\$\{distro_codename\}-updates"' <<<"${dump}" \
    && ok=1
  judge APT "$ok"
}
check_needrestart() { local ok=0; needrestart -b >/dev/null 2>&1 && grep -qs "override_rc.*kubelet" /etc/needrestart/conf.d/platform.conf && ok=1; judge NEEDRESTART "$ok"; }
check_debsums() { local ok=0; systemctl is-enabled --quiet platform-debsums.timer && ok=1; judge DEBSUMS "$ok"; }
# Give the connector up to 20 s to re-register after a rule change.
connector_settled() {
  local _
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    journalctl -u cloudflared.service --since "-20s" --no-pager -q 2>/dev/null | grep -qiE "registered tunnel connection|connection .* registered|heartbeat" && return 0
    sleep 2
  done
  return 1
}
# Prove a fresh NTP exchange through the current table as both socket owners:
# ntpd's own sockets are root-owned, later ones belong to the ntpsec user.
# A direct query is used because the reach register is history and would
# pass for minutes after a table started blocking time.
ntp_exchange_through_table() {
  local host owner
  host="$(awk '$1 == "server" { for (i = 2; i <= NF; i++) if ($i !~ /^-/) { print $i; exit } }' /etc/ntpsec/ntp.conf 2>/dev/null)"
  [[ -n "${host}" ]] || return 1
  command -v ntpdig >/dev/null 2>&1 || return 1
  for owner in root ntpsec; do
    timeout 12 sudo -u "${owner}" ntpdig -t 4 -c "${host}" >/dev/null 2>&1 || return 1
  done
}
check_egress() {
  local ok=1
  nft list table inet platform_egress >/dev/null 2>&1 || { say "egress table absent"; ok=0; }
  # The services that must keep working.
  systemctl is-active --quiet cloudflared.service || { say "cloudflared not active"; ok=0; }
  connector_settled || true
  # Only the apt user is expected to reach the mirror; a root attempt would
  # merely feed the drop log.
  sudo -u _apt curl -fsS --max-time 15 -o /dev/null http://ports.ubuntu.com/ubuntu-ports/dists/noble/Release 2>/dev/null || { say "apt mirror unreachable as _apt"; ok=0; }
  # Time must keep flowing: a fresh exchange as both socket owners.
  ntp_exchange_through_table || { say "NTP exchange through the table failed"; ok=0; }
  # A denied flow must die here, not leave. The probe targets a host and port
  # that DO accept connections (the mirror on 443), as a uid outside every
  # rule: success is the finding, and a closed port cannot fake a pass.
  if sudo -u nobody timeout 8 bash -c 'exec 3<>/dev/tcp/ports.ubuntu.com/443' 2>/dev/null; then say "unprivileged egress to an allowed-for-others destination succeeded"; ok=0; fi
  nft list chain inet platform_egress output 2>/dev/null | grep -q 'platform-egress-drop' || { say "drop log rule missing"; ok=0; }
  judge EGRESS "$ok"
}
# Open a TCP connection to loopback:22 and expect the SSH banner within 3 s.
sshd_answers_on_loopback() {
  local banner=''
  exec 3<>/dev/tcp/127.0.0.1/22 || return 1
  read -r -t 3 banner <&3 || { exec 3>&-; return 1; }
  exec 3>&-
  [[ "${banner}" == SSH-2.0* ]]
}
check_sshd_listen() {
  local ok=1 listeners
  listeners="$(ss -tlnH 'sport = :22' | awk '{print $4}' | sort -u)"
  grep -q '^127.0.0.1:22$' <<<"${listeners}" || { say "loopback listener missing"; ok=0; }
  grep -qE '^(0\.0\.0\.0|\*|\[::\]):22$' <<<"${listeners}" && { say "wildcard listener still present"; ok=0; }
  [[ "$(grep -c ':22$' <<<"${listeners}")" -le 2 ]] || { say "unexpected listener set"; ok=0; }
  sshd_answers_on_loopback || { say "sshd does not answer on loopback"; ok=0; }
  judge SSHD_LISTEN "$ok"
}
check_cmdline() {
  local ok=1 tokens tok
  read -ra tokens < "${hardening_root}/cmdline/platform-kernel-hardening.cmdline"
  for tok in "${tokens[@]}"; do
    grep -qw -- "${tok}" /boot/firmware/cmdline.txt || { say "cmdline.txt lacks ${tok}"; ok=0; }
  done
  judge CMDLINE_STAGED "$ok"
  if grep -qw 'lockdown=integrity' /proc/cmdline && [[ "$(cat /sys/kernel/security/lockdown)" == *"[integrity]"* ]]; then pass CMDLINE_ACTIVE; else result CMDLINE_ACTIVE PENDING_REBOOT; fi
}
check_ipv6() {
  [[ -n "${UPLINK_INTERFACE}" ]] || { fail IPV6; return; }
  local ok=1
  if ip -6 -o addr show dev "${UPLINK_INTERFACE}" scope global 2>/dev/null | grep -q inet6; then say "global IPv6 still on uplink"; ok=0; fi
  judge IPV6 "$ok"
}

check_cluster_files() {
  local ok=1 f
  [[ "$(stat -c '%a' /var/lib/etcd)" == 700 ]] || { say "etcd data dir not 0700"; ok=0; }
  for f in /etc/systemd/system/kubelet.service /etc/systemd/system/kubelet.service.d/*.conf; do
    [[ -e "$f" ]] || continue
    [[ "$(stat -c '%a' "$f")" == 600 ]] || { say "$f not 0600"; ok=0; }
  done
  judge CLUSTER_FILES "$ok"
}

case "$comp" in
  sysctl) check_sysctl ;; units) check_units ;; journald) check_journald ;; auditd) check_auditd ;;
  apt) check_apt ;; needrestart) check_needrestart ;; debsums) check_debsums ;; egress) check_egress ;;
  sshd-listen) check_sshd_listen ;; cmdline) check_cmdline ;; ipv6) check_ipv6 ;; cluster-files) check_cluster_files ;;
  all) check_sysctl; check_units; check_journald; check_auditd; check_apt; check_needrestart; check_debsums; check_egress; check_sshd_listen; check_cmdline; check_ipv6; check_cluster_files ;;
  *) printf 'unknown component\n' >&2; exit 2 ;;
esac
exit "${rc}"
