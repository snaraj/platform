# Host hardening

A reproducible, verifiable baseline for the single-node control-plane host:
what the host runs, what may leave it, what the kernel exposes, and how to
prove each of those from live state rather than from the files on disk.

## What is here

| Path | Purpose |
| --- | --- |
| `host-manifest.sh` | One redacted, diffable snapshot of every host surface. A hardening claim is `diff -r before after`. |
| `baseline-run.sh` | Runs the independent assessors (oscap against the distribution OVAL feed, trivy, grype, lynis, kube-bench, kubescape, ssh-audit, kernel-hardening-checker, `systemd-analyze security`) into one phase directory. |
| `summarize-assessment.py` | Reduces a phase directory to the numbers the pull request cites. |
| `remove-unneeded-surfaces.sh` | Takes off the host what the workload never uses, with a protected-package refusal and a post-removal connectivity check. |
| `apply-hardening.sh` | Installs one component at a time: `sysctl`, `units`, `journald`, `auditd`, `apt`, `needrestart`, `debsums`, `egress`, `sshd-listen`, `cmdline`, `ipv6`, `cluster-files`. Lockout-capable components arm a 10-minute automatic revert that only a passing verifier cancels. |
| `verify-hardening.sh` | Proves each component from kernel and systemd state and prints `HARDENING_<NAME>=PASS|FAIL`. |
| `sysctl/`, `cmdline/`, `systemd/`, `journald/`, `auditd/`, `apt/`, `needrestart/`, `nftables/` | The shipped configuration, one file per surface, each commented with why it exists. |
| `hardening.env.example` | The host-specific inputs. The real file is root-only on the host and never committed. |

## Model

- Inbound is already default-deny; SSH is reachable only from the local
  tunnel connector, which the enrolled devices reach over the private route.
  `sshd-listen` removes the wildcard listener so that remains true even if
  the firewall fails open.
- Outbound becomes a per-service allowlist on the output hook: the connector,
  the apt user, the time daemon, the stub resolver and root image pulls, each
  to the ports they need. Everything else is logged and dropped. The table is
  evaluated before the distribution firewall and flushes only itself.
- The kernel runs in `lockdown=integrity` with signed modules enforced, and
  the allocator and stack hardening the brief names; those take effect at the
  owner's reboot and the verifier says `PENDING_REBOOT` until then.
- Long-running daemons that can be fenced are fenced; sshd is deliberately not,
  because its children are the administrator's own session.
- The journal is sealed; the verification key leaves with the operator.
- Reboots stay with the owner: unattended upgrades are security-only, never
  reboot, and `needrestart` reports what a reboot would clear.

See [operations.md](operations.md) for the procedure and ADR 0018 for the
decisions, including what was evaluated and rejected.
