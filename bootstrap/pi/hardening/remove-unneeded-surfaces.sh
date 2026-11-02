#!/usr/bin/env bash
# remove-unneeded-surfaces.sh — take off the host what its workload never uses.
#
# Usage: sudo remove-unneeded-surfaces.sh <plan|apply>
#
# What goes: an anonymizing-proxy daemon and its tooling, a wallet application
# package, the desktop stack and remote desktop, crash/news telemetry, a
# directory-service client, Bluetooth and modem managers, package-kit, the
# removed snap daemon's stale mount units, an orphaned admin VPN peer, and,
# only when hardening.env names one, a retired validation loop mount.
#
# What stays, on purpose: the network stack (pinned manual before autoremove so
# it can never ride out as a dependency), compilers (a separate decision), and
# every protected legacy archive, which ADR 0013 keeps inert and the owner
# alone may delete.
set -Eeuo pipefail
# shellcheck source=bootstrap/pi/hardening/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
require_root; load_env
action="${1:-}"
export DEBIAN_FRONTEND=noninteractive

purge=(tor tor-geoipdb torsocks sparrowwallet
  ubuntu-desktop ubuntu-desktop-minimal ubuntu-desktop-raspi ubuntu-raspi-settings-desktop
  gdm3 gnome-shell gnome-remote-desktop gnome-control-center gnome-session-canberra gnome-settings-daemon
  gnome-initial-setup nautilus pipewire-pulse wireplumber
  whoopsie apport kerneloops sssd bluez modemmanager
  update-notifier update-manager software-properties-gtk ubuntu-release-upgrader-gtk
  language-selector-gnome xdg-user-dirs-gtk zenity dmz-cursor-theme pemmican-desktop
  gstreamer1.0-packagekit packagekit snapd
  pulseaudio pulseaudio-utils libasound2-plugins)
# Never allowed to leave as a side effect of the purge or autoremove.
protected='^(network-manager|wpasupplicant|netplan\.io|linux-(image|modules|firmware|raspi)[a-z0-9.+-]*|openssh-(server|client)|sudo|systemd|udev|dbus|polkitd|wireguard|nftables|ufw|iproute2|containerd|cloudflared|ntpsec|rsyslog|cron|ca-certificates|apt|dpkg|python3|wireless-regdb|bluez-firmware|libnss-(systemd|resolve)|ubuntu-pro-client|ubuntu-(minimal|standard|raspi-settings)|unattended-upgrades|systemd-oomd|needrestart|debsums|auditd)$'
keep_manual=(network-manager wpasupplicant netplan.io linux-firmware-raspi linux-image-raspi openssh-server sudo wireguard wireguard-tools nftables ufw iproute2 ntpsec cloudflared rsyslog cron ca-certificates python3 curl
  unattended-upgrades systemd-oomd rfkill jq unzip zip python3-systemd ubuntu-raspi-settings)

installed() { dpkg-query -W -f '${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^i'; }
present_targets() { local p; for p in "${purge[@]}"; do dpkg-query -W -f '${db:Status-Abbrev}\n' "$p" 2>/dev/null | grep -qE '^(i|r)' && printf '%s\n' "$p"; done; }

simulate() {
  mapfile -t targets < <(present_targets)
  [[ ${#targets[@]} -gt 0 ]] || { say "nothing left to purge"; return 0; }
  apt-get -s purge "${targets[@]}" 2>&1 | awk '/^(Remv|Purg)/{print $2}' | sort -u
}

plan() {
  say "== packages that would leave:"; simulate | tr '\n' ' '; echo
  say "== protected names among them (must be empty):"; simulate | grep -E "${protected}" || say "none"
  say "== stale snap mount units: $(find /etc/systemd/system -maxdepth 1 -name 'snap-*.mount' | wc -l)"
  [[ -n "${STALE_MOUNT_UNIT}" ]] && say "== stale mount: ${STALE_MOUNT_UNIT} -> ${STALE_MOUNT_ROOT}"
  [[ -n "${ORPHAN_WG_INTERFACE}" ]] && say "== orphan admin VPN: wg-quick@${ORPHAN_WG_INTERFACE} (udp ${ORPHAN_WG_PORT:-?})"
  say "== accounts to remove: debian-tor $(getent passwd debian-tor >/dev/null && echo present || echo absent)"
}

apply() {
  if simulate | grep -qE "${protected}"; then say "refusing: the purge would remove a protected package"; result REMOVE FAIL; exit 1; fi
  apt-mark manual "${keep_manual[@]}" >/dev/null 2>&1 || true
  mapfile -t targets < <(present_targets)
  if [[ ${#targets[@]} -gt 0 ]]; then apt-get -y -q purge "${targets[@]}"; fi
  if apt-get -s autoremove --purge 2>&1 | awk '/^(Remv|Purg)/{print $2}' | grep -qE "${protected}"; then
    say "refusing autoremove: it would take a protected package"; result REMOVE FAIL; exit 1
  fi
  apt-get -y -q autoremove --purge
  systemctl set-default multi-user.target >/dev/null
  # News fetches on login are telemetry with no operator value.
  [[ -f /etc/default/motd-news ]] && sed -i 's/^ENABLED=1/ENABLED=0/' /etc/default/motd-news
  systemctl disable --now motd-news.timer >/dev/null 2>&1 || true
  # Stale snap mounts: the daemon is gone, the units were left behind.
  for u in /etc/systemd/system/snap-*.mount; do [[ -e "$u" ]] || continue; systemctl disable --now "$(basename "$u")" >/dev/null 2>&1 || true; rm -f "$u"; done
  rm -rf /var/lib/snapd /snap
  # The proxy daemon's state (onion keys live there) and account.
  if [[ -d /var/lib/tor ]]; then find /var/lib/tor -type f -exec shred -u {} + 2>/dev/null || true; rm -rf /var/lib/tor; fi
  rm -rf /etc/tor /var/log/tor /run/tor
  getent passwd debian-tor >/dev/null && deluser --system debian-tor >/dev/null 2>&1 || true
  # Stale validation rig.
  if [[ -n "${STALE_MOUNT_UNIT}" ]]; then
    systemctl disable --now "${STALE_MOUNT_UNIT}" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${STALE_MOUNT_UNIT}"
    [[ -n "${STALE_MOUNT_ROOT}" && -d "${STALE_MOUNT_ROOT}" ]] && { losetup -j "${STALE_MOUNT_ROOT}"/*.ext4 2>/dev/null | cut -d: -f1 | xargs -r -n1 losetup -d; rm -rf "${STALE_MOUNT_ROOT}"; }
    systemctl daemon-reload
  fi
  # Orphaned admin VPN peer: unit, firewall rule, configuration (key material).
  if [[ -n "${ORPHAN_WG_INTERFACE}" ]]; then
    systemctl disable --now "wg-quick@${ORPHAN_WG_INTERFACE}" >/dev/null 2>&1 || true
    [[ -n "${ORPHAN_WG_PORT}" ]] && { ufw --force delete allow "${ORPHAN_WG_PORT}/udp" >/dev/null 2>&1 || true; }
    [[ -f "/etc/wireguard/${ORPHAN_WG_INTERFACE}.conf" ]] && shred -u "/etc/wireguard/${ORPHAN_WG_INTERFACE}.conf"
  fi
  systemctl daemon-reload
  verify
}

verify() {
  local ok=1
  for p in "${purge[@]}"; do installed "$p" && { say "still installed: $p"; ok=0; }; done
  pgrep -x tor >/dev/null && { say "tor process alive"; ok=0; }
  getent passwd debian-tor >/dev/null && { say "debian-tor account remains"; ok=0; }
  [[ -d /var/lib/tor || -d /etc/tor ]] && { say "tor directories remain"; ok=0; }
  systemctl list-unit-files --no-legend 'tor*' 'snap-*' 'gdm*' 'gnome-remote-desktop*' 2>/dev/null | grep -q . && { say "stale units remain"; ok=0; }
  [[ -n "${ORPHAN_WG_INTERFACE}" ]] && ip link show "${ORPHAN_WG_INTERFACE}" >/dev/null 2>&1 && { say "orphan VPN interface still up"; ok=0; }
  [[ -n "${STALE_MOUNT_UNIT}" ]] && systemctl is-active --quiet "${STALE_MOUNT_UNIT}" && { say "stale mount still active"; ok=0; }
  if ! systemctl is-active --quiet NetworkManager || ! ip -4 route show default | grep -q .; then say "network stack unhealthy"; ok=0; fi
  systemctl is-active --quiet cloudflared.service || { say "tunnel connector down"; ok=0; }
  systemctl is-active --quiet kubelet.service || { say "kubelet down"; ok=0; }
  [[ "$(systemctl get-default)" == multi-user.target ]] || { say "default target not multi-user"; ok=0; }
  if [[ $ok -eq 1 ]]; then result REMOVE PASS; else result REMOVE FAIL; exit 1; fi
}

case "$action" in plan) plan ;; apply) apply ;; verify) verify ;; *) printf 'usage: %s <plan|apply|verify>\n' "$0" >&2; exit 2 ;; esac
