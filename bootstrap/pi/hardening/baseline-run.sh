#!/usr/bin/env bash
# baseline-run.sh — run every independent assessor once and keep its raw output.
#
# Why: the hardening claim is judged by tools nobody on this project wrote.
# Each run writes into <job-dir>/<phase>/ so "before" and "after" sit side by
# side. The scanners live under <job-dir>/tools (verified release binaries or
# archive packages); caches stay inside <job-dir> so cleanup is one rm.
#
# Usage: sudo baseline-run.sh <job-dir> <phase>
set -uo pipefail
job="${1:-}"; phase="${2:-before}"
[[ -n "${job}" && -d "${job}" ]] || { printf 'usage: %s <job-dir> <phase>\n' "$0" >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 2; }
out="${job}/${phase}"; tools="${job}/tools"
install -d -m 0700 "${out}" "${job}/home" "${job}/cache"
export HOME="${job}/home" XDG_CACHE_HOME="${job}/cache" LC_ALL=C
export TRIVY_CACHE_DIR="${job}/cache/trivy" GRYPE_DB_CACHE_DIR="${job}/cache/grype"
export CONTAINERD_ADDRESS=/run/containerd/containerd.sock CONTAINERD_NAMESPACE=k8s.io
export KUBECONFIG=/etc/kubernetes/admin.conf
# User data is not the host; container state is scanned through the images.
skip=/proc,/sys,/dev,/run,/home,/var/lib/containerd,/var/lib/kubelet,/tmp
step() { printf '\n== %s  %s\n' "$(date -u +%FT%TZ)" "$*" >> "${out}/run.log"; }
renice -n 15 $$ >/dev/null 2>&1; ionice -c 3 -p $$ >/dev/null 2>&1

step manifest;      bash "$(dirname "$0")/host-manifest.sh" "${out}/manifest" >> "${out}/run.log" 2>&1
step unit-security; systemd-analyze security --no-pager > "${out}/systemd-security.txt" 2>&1
for u in ssh.service cloudflared.service ntpsec.service containerd.service kubelet.service unattended-upgrades.service; do
  systemd-analyze security --no-pager "$u" > "${out}/systemd-security-${u}.txt" 2>&1
done
step ssh-audit;     ssh-audit -p 22 127.0.0.1 > "${out}/ssh-audit.txt" 2>&1
step khc;           sysctl -a > "${out}/sysctl-all.txt" 2>/dev/null
python3 "${tools}/khc/bin/kernel-hardening-checker" -c "/boot/config-$(uname -r)" -l /proc/cmdline -s "${out}/sysctl-all.txt" > "${out}/kernel-hardening-checker.txt" 2>&1
step lynis;         lynis audit system --quiet --no-colors --logfile "${out}/lynis.log" --report-file "${out}/lynis-report.dat" > "${out}/lynis.txt" 2>&1
step oscap;         oscap oval eval --results "${out}/oscap-results.xml" --report "${out}/oscap-report.html" "${job}/oval.xml" > "${out}/oscap.txt" 2>&1
step kube-bench;    cfg=$(find "${tools}/kb/cfg" -mindepth 1 -maxdepth 1 -type d -name 'cis-*' | sort -V | tail -1)
"${tools}/kb/kube-bench" run --config-dir "${tools}/kb/cfg" --benchmark "$(basename "$cfg")" --json > "${out}/kube-bench.json" 2> "${out}/kube-bench.err"
"${tools}/kb/kube-bench" run --config-dir "${tools}/kb/cfg" --benchmark "$(basename "$cfg")" > "${out}/kube-bench.txt" 2>&1
step kubescape;     [[ -x "${tools}/kubescape" ]] && "${tools}/kubescape" scan framework nsa,cis-v1.10.0 --kubeconfig "${KUBECONFIG}" --format json --output "${out}/kubescape.json" > "${out}/kubescape.txt" 2>&1
step trivy-rootfs;  "${tools}/trivy/trivy" rootfs --scanners vuln --severity CRITICAL,HIGH,MEDIUM --format json --output "${out}/trivy-rootfs.json" --skip-dirs "${skip}" / >> "${out}/run.log" 2>&1
step trivy-images;  crictl -r "unix://${CONTAINERD_ADDRESS}" images --digests --no-trunc 2>/dev/null | awk 'NR>1 && $1!="<none>" {print $1"@"$3}' | sort -u > "${out}/images.txt"
mkdir -p "${out}/trivy-images"
while read -r img; do
  f=$(printf '%s' "$img" | tr '/:@' '___')
  "${tools}/trivy/trivy" image --image-src containerd --scanners vuln --severity CRITICAL,HIGH --format json --output "${out}/trivy-images/${f}.json" "$img" >> "${out}/run.log" 2>&1
done < "${out}/images.txt"
step grype-rootfs;  "${tools}/trivy/trivy" rootfs --format cyclonedx --output "${out}/rootfs.cdx.json" --skip-dirs "${skip}" / >> "${out}/run.log" 2>&1
"${tools}/grype/grype" "sbom:${out}/rootfs.cdx.json" -o json --file "${out}/grype-rootfs.json" >> "${out}/run.log" 2>&1
step finished;      printf 'BASELINE_RUN=DONE phase=%s\n' "${phase}" >> "${out}/run.log"
