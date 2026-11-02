# Host hardening procedures

Everything below runs as root on the host from a checkout of this directory.
Nothing here authorizes a reboot, the deletion of persistent data, or a change
to the private route; those remain the owner's.

## 0. Inputs

Create `/etc/platform-hardening/hardening.env` (root:root 0600) from
`hardening.env.example`. Every value is private inventory for one host.

## 1. Baseline

```sh
install -d -m 0700 "$JOB"          # a scratch directory the run owns
# tools: verified release binaries under $JOB/tools (trivy, grype, kube-bench,
# kubescape, kernel-hardening-checker); oscap, lynis, ssh-audit, nmap,
# debsums, needrestart from the distribution archive; the distribution's
# USN OVAL feed at $JOB/oval.xml
baseline-run.sh "$JOB" before
summarize-assessment.py "$JOB/before"
```

## 2. Remove

```sh
remove-unneeded-surfaces.sh plan     # read the list; the protected set must be empty
remove-unneeded-surfaces.sh apply    # refuses if a protected package would leave
```

The script pins the network stack `manual` before `autoremove`, switches the
default target to `multi-user`, removes stale snap mount units, the proxy
daemon's state and account, the orphaned admin VPN peer and, only if the env
file names one, a retired validation loop mount, then checks that the network, the tunnel
connector and kubelet are still up.

## 3. Apply, one component at a time

```sh
for c in sysctl units journald auditd apt needrestart debsums; do
  apply-hardening.sh plan "$c" && apply-hardening.sh apply "$c"
done
apply-hardening.sh apply egress        # armed with a 10-minute revert
apply-hardening.sh apply sshd-listen   # armed with a 10-minute revert
apply-hardening.sh apply ipv6
apply-hardening.sh apply cluster-files
apply-hardening.sh apply cmdline       # staged; the owner reboots
verify-hardening.sh all
```

`egress` and `sshd-listen` schedule an automatic revert with `systemd-run`
before they change anything. If the verifier passes the timer is cancelled
and the change is persisted; if it fails, or the session is lost, the host
reverts itself.

### Journal sealing key

`journalctl --setup-keys --interval=15min` prints the verification key once.
Run it from the operator's own session, capture the output into the
laptop-only operator folder, and never write it on the host. Verify later with
`journalctl --verify --verify-key=<key>`.

## 4. After

```sh
baseline-run.sh "$JOB" after
summarize-assessment.py "$JOB/after"
diff -r "$JOB/before/manifest" "$JOB/after/manifest"
```

## 5. Revert

```sh
apply-hardening.sh revert <component>   # restores from the newest backup
```

Backups live under `/var/backups/platform-hardening/<timestamp>/`. A plain
`git revert` of this directory changes nothing on a host; revert on the host.

## Kernel command line

`cmdline` edits `/boot/firmware/cmdline.txt` in place, keeping a backup. If
the host does not come back after the reboot, the owner restores the backup
from the boot partition on another machine. The kernel on this host has the
lockdown LSM built in and module signing enabled; the verifier checks the
live `/sys/kernel/security/lockdown` after the reboot.

## Per-key justification (sysctl)

- `kptr_restrict=2`, `dmesg_restrict=1`: no kernel addresses to any user.
- `yama.ptrace_scope=2`: only root may attach a debugger.
- `kexec_load_disabled=1`, `sysrq=0`: no runtime kernel replacement, no magic keys.
- `perf_event_paranoid=3`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`:
  no unprivileged kernel-side execution surfaces.
- `io_uring_disabled=2`: the single largest recent source of kernel LPEs, and
  nothing on this host uses it.
- `fs.protected_*`, `suid_dumpable=0`, `unprivileged_userfaultfd=0`,
  `ldisc_autoload=0`: classic local escalation primitives.
- Network keys: no redirects, no source routing, martians logged, syncookies,
  no router advertisements (IPv6 is disabled on the uplink by policy).
