#!/usr/bin/env bash
# host-manifest.sh — produce a redacted, diffable snapshot of a Pi-class control-plane host.
#
# Why this exists: a hardening claim is a diff between two manifests produced
# by the same code. This script is that code. It writes one file per surface
# so `diff -r before after` reads as a change list, redacts addresses and
# identifiers so the bundle can be discussed without leaking inventory, and
# never prints key material (keys are counted, never copied).
#
# Usage: sudo host-manifest.sh <output-dir>
# Exit 0 after writing <output-dir>/MANIFEST.sha256; non-zero only on misuse.
# shellcheck disable=SC2016 # every section passes a literal command string to bash -c.
set -uo pipefail

out="${1:-}"
[[ -n "${out}" ]] || { printf 'usage: %s <output-dir>\n' "$0" >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { printf 'run as root (sudo) so every surface is readable\n' >&2; exit 2; }
install -d -m 0700 "${out}"
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
kubeconfig=/etc/kubernetes/admin.conf

# redact: IPv4, global/link IPv6, MAC addresses and e-mail-shaped tokens.
# Applied only to network-shaped surfaces; package versions are left alone.
redact() {
  # Each address expression loops (label, substitute, branch-if-substituted)
  # because the delimiter it consumes would otherwise leave every second
  # address of a run untouched.
  sed -E \
    -e ':a' -e 's/(^|[^0-9.])(([0-9]{1,3}\.){3}[0-9]{1,3})([^0-9.]|$)/\1<ip4>\4/' -e 'ta' \
    -e ':b' -e 's/(^|[^0-9a-fA-F:])([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}([^0-9a-fA-F:]|$)/\1<mac>\3/' -e 'tb' \
    -e ':c' -e 's/(^|[^0-9a-fA-F:<])(fe80|fd[0-9a-fA-F]{2}|2[0-9a-fA-F]{3}):[0-9a-fA-F:]+(%[a-z0-9]+)?/\1<ip6>/' -e 'tc' \
    -e 's/\[::\]/<ip6any>/g' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<email>/g'
}

# section NAME REDACT(yes|no) -- command...
section() {
  local name="$1" red="$2"; shift 2
  local file="${out}/${name}.txt"
  if [[ "${red}" == yes ]]; then
    { "$@" 2>&1 || printf '\n[exit %s]\n' "$?"; } | redact > "${file}"
  else
    { "$@" 2>&1 || printf '\n[exit %s]\n' "$?"; } > "${file}"
  fi
}

# ---- system -----------------------------------------------------------------
section 00-system yes bash -c '
  lsb_release -ds; uname -r; uname -m; printf "cmdline: "; cat /proc/cmdline
  printf "lockdown: "; cat /sys/kernel/security/lockdown 2>/dev/null
  printf "boot: "; uptime -s
  printf "secureboot/eeprom: "; rpi-eeprom-update 2>/dev/null | grep -E "CURRENT|LATEST" | tr "\n" " "; echo
  printf "zswap: "; cat /sys/module/zswap/parameters/enabled 2>/dev/null'

# ---- packages ---------------------------------------------------------------
section 10-packages no bash -c 'dpkg-query -W -f "\${binary:Package}\t\${Version}\t\${Architecture}\t\${db:Status-Abbrev}\n" | sort'
section 11-manual no bash -c 'apt-mark showmanual | sort'
section 12-upgradable no bash -c 'apt list --upgradable 2>/dev/null | sed 1d | sort'
section 13-security-status no bash -c '(pro security-status 2>/dev/null || ubuntu-security-status 2>/dev/null); echo "--- third party / unavailable"; ubuntu-security-status --thirdparty --unavailable 2>/dev/null | grep -vE "^$"'
section 14-debsums-changed no bash -c 'debsums -c 2>&1 | sort'
section 15-apt-sources no bash -c '
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do [ -f "$f" ] && { echo "== $f"; grep -vE "^\s*(#|$)" "$f"; }; done
  echo "== keyrings"; sha256sum /etc/apt/trusted.gpg.d/* /etc/apt/keyrings/* /usr/share/keyrings/* 2>/dev/null | sort -k2
  echo "== apt conf"; for f in /etc/apt/apt.conf.d/*; do echo "-- $f"; grep -vE "^\s*(//|$)" "$f"; done'

# ---- network ----------------------------------------------------------------
section 20-nft-ruleset yes nft list ruleset
section 21-ufw yes bash -c 'ufw status verbose; echo "== before.rules custom"; sed -n "/^# BEGIN/,/^# END/p" /etc/ufw/before.rules 2>/dev/null; grep -nE "^-A ufw-before" /etc/ufw/before.rules /etc/ufw/before6.rules 2>/dev/null | grep -vE "ufw-before-(input|output|forward) -(i lo|o lo|m conntrack|p icmp|p udp --sport 67|s 224|d 224)" | head -80'
section 22-interfaces yes bash -c 'ip -d -o link show; echo "== addr"; ip -o addr show; echo "== routes (all tables)"; ip route show table all; echo "== rules"; ip rule; echo "== v6 rules"; ip -6 rule; echo "== v6 routes"; ip -6 route show table all'
section 23-sockets yes bash -c 'ss -tulpnH | awk "{print \$1, \$5, \$7}" | sort'
section 24-sysctl no bash -c 'sysctl -a 2>/dev/null | grep -vE "^(fs\.(binfmt_misc|quota)|net\.(ipv4|ipv6)\.(conf|neigh)\.(cali|vxlan|wg)|dev\.|kernel\.sched_domain|kernel\.random\.(boot_id|uuid))" | sort'
section 25-modules no bash -c 'lsmod | awk "NR>1{print \$1}" | sort; echo "== modprobe.d"; for f in /etc/modprobe.d/*; do echo "-- $f"; grep -vE "^\s*(#|$)" "$f"; done; echo "== modules-load.d"; cat /etc/modules-load.d/* 2>/dev/null | grep -vE "^\s*(#|$)"'
section 26-resolved yes resolvectl status
section 27-wireguard yes bash -c 'wg show interfaces; for i in $(wg show interfaces); do echo "== $i"; wg show "$i" listen-port; wg show "$i" fwmark; wg show "$i" peers | wc -l | sed "s/^/peers: /"; done; echo "== units"; systemctl list-units --no-legend "wg-quick@*"'
section 28-radios no bash -c 'rfkill list 2>/dev/null; systemctl is-enabled bluetooth.service ModemManager.service wpa_supplicant.service 2>&1 | paste <(printf "bluetooth\nModemManager\nwpa_supplicant\n") -'

# ---- services ---------------------------------------------------------------
section 30-units-enabled no bash -c 'systemctl list-unit-files --state=enabled --no-legend | awk "{print \$1}" | sort'
section 31-units-running no bash -c 'systemctl list-units --type=service --state=running --no-legend | awk "{print \$1}" | sort'
section 32-timers no bash -c 'systemctl list-timers --all --no-legend | awk "{print \$NF}" | sort'
section 33-unit-security no bash -c 'systemd-analyze security --no-pager 2>/dev/null | sed 1d | sort -k2 -nr'
section 34-sockets-units no bash -c 'systemctl list-sockets --all --no-legend | awk "{print \$1, \$2}" | sort'
section 35-journald no bash -c 'cat /etc/systemd/journald.conf.d/* 2>/dev/null | grep -vE "^\s*(#|$)"; echo "== fss"; ls -la /var/log/journal/*/fss 2>/dev/null | awk "{print \$1, \$9}"; journalctl --disk-usage'
section 36-unattended no bash -c 'cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -vE "^\s*(//|$)"; echo "== needrestart"; needrestart -b 2>/dev/null; echo "== auditd"; systemctl is-enabled auditd 2>&1; auditctl -l 2>/dev/null | head -50'

# ---- access control ---------------------------------------------------------
section 40-apparmor no bash -c 'aa-status 2>/dev/null | grep -E "profiles are|processes are"; echo "== unconfined-mode profiles"; aa-status --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); [print(k) for k,v in sorted(d.get(\"profiles\",{}).items()) if v==\"unconfined\"]"; echo "== running unconfined processes"; aa-status 2>/dev/null | sed -n "/processes are unconfined/,/processes are in/p" | grep -E "^\s+/" | awk "{print \$1}" | sort -u'
section 41-suid no bash -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %u %g %p\n" 2>/dev/null | sort -k4'
section 42-sudoers yes bash -c 'grep -vE "^\s*(#|$)" /etc/sudoers; for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "== $f"; grep -vE "^\s*(#|$)" "$f"; }; done'
section 43-users yes bash -c '
  echo "== login-capable accounts"; getent passwd | awk -F: "\$7 !~ /(nologin|false|sync)$/ {print \$1\":\"\$3\":\"\$6\":\"\$7}"
  echo "== authorized_keys (counted, never copied)"
  for h in /root $(getent passwd | awk -F: "\$3>=1000 && \$3<65534 {print \$6}"); do
    f="$h/.ssh/authorized_keys"; [ -f "$f" ] || continue
    printf "%s: %s key(s): " "$h" "$(grep -cE "^(ssh|sk-|ecdsa)" "$f")"; awk "/^(ssh|sk-|ecdsa)/{print \$1}" "$f" | sort | uniq -c | tr "\n" " "; echo
  done
  echo "== groups of interest"; for g in sudo adm docker lxd; do printf "%s: " $g; getent group $g | cut -d: -f4; done
  echo "== password aging"; awk -F: "\$2 !~ /^[!*]/ {print \$1\": has-password\"}" /etc/shadow'
section 44-sshd yes bash -c 'sshd -T 2>/dev/null | sort; echo "== config.d"; ls -la /etc/ssh/sshd_config.d/ | awk "{print \$1, \$9}"; echo "== host keys (types only)"; for k in /etc/ssh/ssh_host_*_key.pub; do awk "{print \$1}" "$k"; done; echo "== listen"; systemctl cat ssh.socket 2>/dev/null | grep -E "^Listen"'
section 45-cron no bash -c 'ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null | awk "{print \$1, \$9}"; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -vE "^\s*(#|$)" | sed "s/^/$u: /"; done'
section 46-local-binaries no bash -c 'for d in /usr/local/sbin /usr/local/bin /opt; do echo "== $d"; ls -la "$d" 2>/dev/null | awk "NR>1{print \$1, \$3, \$5, \$9, \$10, \$11}"; done; echo "== sha256 /usr/local/{s,}bin"; find /usr/local/sbin /usr/local/bin -maxdepth 1 -type f -exec sha256sum {} + 2>/dev/null | sort -k2'
section 47-mounts yes bash -c 'findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS | grep -vE "^/(proc|sys|dev|run)(/|$)" | sort; echo "== loop"; losetup -a; echo "== df"; df -h -x tmpfs -x devtmpfs -x overlay | sed 1d; echo "== fstab"; grep -vE "^\s*(#|$)" /etc/fstab'

# ---- kubernetes -------------------------------------------------------------
section 50-kubelet-config yes bash -c 'cat /var/lib/kubelet/config.yaml; echo "== kubelet drop-ins"; for f in /etc/systemd/system/kubelet.service.d/*; do echo "-- $f"; grep -vE "^\s*(#|$)" "$f"; done'
section 51-control-plane-manifests yes bash -c 'for f in /etc/kubernetes/manifests/*.yaml; do echo "== $f"; grep -E "^\s+- --" "$f" | sed -E "s/(--[a-z-]*(token|key|cert|ca)[a-z-]*=)[^ ]*/\1<path>/"; done; echo "== psa/audit/encryption files"; ls -la /etc/kubernetes/encryption /etc/kubernetes/*.yaml 2>/dev/null | awk "{print \$1, \$9}"'
section 52-images no bash -c 'crictl -r unix:///run/containerd/containerd.sock images --digests --no-trunc 2>/dev/null | awk "NR>1{print \$1\":\"\$2, \$3}" | sort'
section 53-containerd no bash -c 'containerd --version; runc --version | head -1; grep -vE "^\s*(#|$)" /etc/containerd/config.toml 2>/dev/null | head -60'
section 54-netpol yes bash -c 'KUBECONFIG='"${kubeconfig}"' kubectl get networkpolicies -A -o json | python3 -c "
import sys,json
for i in json.load(sys.stdin)[\"items\"]:
    s=i[\"spec\"]; print(i[\"metadata\"][\"namespace\"]+\"/\"+i[\"metadata\"][\"name\"], \"types=\"+\",\".join(s.get(\"policyTypes\",[])), \"ingressRules=%d\"%len(s.get(\"ingress\",[]) or []), \"egressRules=%d\"%len(s.get(\"egress\",[]) or []), \"selector=\"+json.dumps(s.get(\"podSelector\",{}),sort_keys=True))"'
section 55-rbac no bash -c 'KUBECONFIG='"${kubeconfig}"' kubectl get clusterrolebindings -o json | python3 -c "
import sys,json
for i in json.load(sys.stdin)[\"items\"]:
    subs=[(s.get(\"kind\"),s.get(\"namespace\",\"\"),s[\"name\"]) for s in i.get(\"subjects\",[]) or []]
    print(i[\"metadata\"][\"name\"], \"->\", i[\"roleRef\"][\"name\"], subs)" | grep -vE "^system:" | sort'
section 56-workloads yes bash -c 'KUBECONFIG='"${kubeconfig}"' kubectl get pods -A -o json | python3 -c "
import sys,json
for p in json.load(sys.stdin)[\"items\"]:
    m=p[\"metadata\"]; s=p[\"spec\"]
    flags=[]
    if s.get(\"hostNetwork\"): flags.append(\"hostNetwork\")
    if s.get(\"hostPID\"): flags.append(\"hostPID\")
    for c in s[\"containers\"]:
        sc=c.get(\"securityContext\") or {}
        if sc.get(\"privileged\"): flags.append(\"privileged:\"+c[\"name\"])
        if (sc.get(\"capabilities\") or {}).get(\"add\"): flags.append(\"caps:\"+c[\"name\"]+\"=\"+\",\".join(sc[\"capabilities\"][\"add\"]))
    for v in s.get(\"volumes\",[]) or []:
        if \"hostPath\" in v: flags.append(\"hostPath:\"+v[\"hostPath\"][\"path\"])
    print(m[\"namespace\"]+\"/\"+m[\"name\"].rsplit(\"-\",1)[0], p[\"status\"][\"phase\"], \" \".join(flags))" | sort -u
echo "== namespace pod-security labels"; KUBECONFIG='"${kubeconfig}"' kubectl get ns -o json | python3 -c "
import sys,json
for n in json.load(sys.stdin)[\"items\"]:
    l={k.split(\"/\")[1]:v for k,v in (n[\"metadata\"].get(\"labels\") or {}).items() if k.startswith(\"pod-security\")}
    print(n[\"metadata\"][\"name\"], l)"'
section 57-flux no bash -c 'KUBECONFIG='"${kubeconfig}"' kubectl -n flux-system get deploy -o json | python3 -c "
import sys,json
for d in json.load(sys.stdin)[\"items\"]:
    for c in d[\"spec\"][\"template\"][\"spec\"][\"containers\"]: print(d[\"metadata\"][\"name\"], c[\"image\"])"'

# ---- integrity --------------------------------------------------------------
section 60-boot-firmware no bash -c 'grep -vE "^\s*(#|$)" /boot/firmware/config.txt 2>/dev/null; echo "== cmdline.txt"; cat /boot/firmware/cmdline.txt 2>/dev/null; echo "== eeprom config"; rpi-eeprom-config 2>/dev/null'
section 61-etc-tracked no bash -c 'ls -la /etc/platform-hardening /etc/*-admin-target /etc/host-audit* 2>/dev/null | awk "{print \$1, \$3, \$9}"; echo "== /etc mtimes newer than 30d (paths only)"; find /etc -xdev -type f -mtime -30 -printf "%TY-%Tm-%Td %p\n" 2>/dev/null | sort | tail -80'

# ---- checksum the bundle ----------------------------------------------------
( cd "${out}" && sha256sum ./*.txt > MANIFEST.sha256 )
printf 'HOST_MANIFEST=OK files=%s dir=%s\n' "$(find "${out}" -name '*.txt' | wc -l | tr -d ' ')" "${out}"
