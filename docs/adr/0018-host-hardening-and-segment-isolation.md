# ADR 0018: Host hardening baseline and network segment isolation

- Status: Accepted (host baseline); Proposed (segment isolation, owner decisions open)
- Date: 2026-11-02

## Context

The single-node control-plane host had grown a surface its workload never
needed: an anonymizing-proxy daemon, a wallet application, a full desktop with
a remote-desktop service, compilers, telemetry, a directory-service client,
an orphaned admin VPN peer with an open inbound UDP rule, and a validation
loop mount with its own LAN-bound TLS listener left over from a September
validation run. Every long-running unit scored UNSAFE in
`systemd-analyze security`; kernel lockdown was off; 90 AppArmor profiles were
unconfined; IPv6 was live on the uplink despite a global sysctl; egress was
"anything through the VPN interface".

The owner's threat model (2026-11-01): the laptop is an accepted physical
liability provided nothing creates a remote-code-execution path onto it;
zero spend; only the owner's enrolled devices reach the host, through WARP
into a Cloudflare private route; applications leave only through the
Cloudflare tunnels; the host stays restricted, not airgapped.

Two facts decided the design. First, `ssh` from the laptop already rides the
WARP interface to the local tunnel connector, which dials sshd on an address
bound to loopback; the only firewall rule admitting port 22 accepts
connections originated by the connector's uid. The host therefore needs no
inbound LAN access at all. Second, the home gateway is an ISP-supplied unit of a class that rarely
offers VLANs (vendor and firmware line are recorded in the laptop-only
operator notes); its real capabilities must be read from its own admin pages.

## Decision

1. **Measure, change, measure.** `bootstrap/pi/hardening/host-manifest.sh`
   produces a redacted, diffable manifest; `baseline-run.sh` runs the
   independent assessors. Every claim in the pull request is a number from
   those tools before and after.
2. **Remove rather than configure.** `remove-unneeded-surfaces.sh` purges the
   list in its header, pins the network stack before `autoremove`, and
   refuses if a protected package would leave.
3. **Per-service egress allowlist** as `table inet platform_egress` on the
   output hook at priority -10, keyed on socket uid, with a logged drop.
   A reload creates the table if absent and empties only that table before
   declaring its rules again, so it coexists with the distribution firewall,
   the CNI and the VPN and never duplicates rules. It is independent of
   whether the VPN stays.
4. **Kernel** `lockdown=integrity module.sig_enforce=1 init_on_alloc=1
   init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on`
   staged in the boot command line, plus the sysctl set in
   `sysctl/99-zz-platform-kernel-hardening.conf`. Effective at the owner's reboot.
5. **Unit sandboxing** for the connector and the time daemon to the limit each
   tolerates. **The container runtime and kubelet are not sandboxed**: even
   the fences that look free are not. `ProtectHome` and `ProtectKernelLogs`
   put the unit in a mount namespace with slave propagation, so kubelet's
   pod volumes never reach the runtime; `ProtectHostname` installs a seccomp
   filter on `sethostname` that every shim and container inherits, so no
   sandbox can start; `ProtectKernelLogs` hides `/dev/kmsg`, which kubelet's
   OOM watcher needs at start-up. The first cut of this change shipped such
   drop-ins and the adversarial review caught it before any restart; the
   test suite now forbids any drop-in for those two units. **sshd is not
   sandboxed**: systemd sandboxing is inherited by every child, and sshd's
   children are the administrator's session (`NoNewPrivileges` alone would
   break `sudo`). OpenSSH's own privilege separation and seccomp remain its
   defense.
6. **sshd listens on loopback and the admin target only**; the wildcard
   listener goes.
7. **IPv6 disabled on the uplink connection** at the network manager, not
   by sysctl alone, which the manager was silently overriding.
8. **Journal sealing** (Forward Secure Sealing) with the verification key
   held off-host by the operator.
9. **Patch cadence**: unattended upgrades security-only, `needrestart`
   restarting ordinary services and never the runtime or kubelet,
   `Automatic-Reboot` off, a daily `debsums` integrity timer, a minimal
   `auditd` rule set (root interactive execs, module loads, writes to `/etc`,
   the boot partition and the local binaries).

## Decisions recorded as deviations from the commission

- **kured is not installed.** It exists to reboot nodes automatically, which
  contradicts the owner-reboots rule, and on a single node draining has
  nothing to drain to. The reboot-required signal is surfaced by `needrestart`
  and the manifest instead.
- **No homegrown replacements.** The bar for replacing a dependency was:
  memory-safe, actively maintained, published security policy, packaged for
  arm64 by the distribution with security maintenance, reversible.
  - `ntpd-rs` vs NTPSec: the archive carries `ntpd-rs` 1.1.2 and NTPSec 1.2.2,
    both in *universe*, so neither has guaranteed security maintenance
    without an ESM subscription; the packaged `ntpd-rs` is two years behind
    upstream. Installing upstream builds would make this repository its own
    supply chain. **No-go now.** NTPSec stays, sandboxed and bound.
  - `sudo-rs` vs sudo: `sudo-rs` 0.2.2 is in *universe*; `sudo` is in *main*
    with security maintenance. **No-go on this release.**
  - Both flip at the next LTS, which ships `sudo-rs` and the Rust coreutils as
    defaults. That is the professional route to memory-safe system tools:
    take them from the distribution that maintains them.
- **Pi 5 signed boot** is one-time programmable and irreversible. Described,
  not enabled.
- **Compilers and build tools stay.** The owner declared this host the
  development environment; removing the toolchain is a separate decision,
  listed below, not a hardening default.

## Network segment isolation (proposed; owner decisions)

Goal: the host on its own segment; no traffic between it and any home device
in either direction; the owner's enrolled devices reach it only through WARP
into the private route, exactly as `ssh` works today, so the owner's path does
not change.

Design, in order of preference, decided by what the gateway's admin pages
show:

1. **Gateway supports VLANs or a firewalled isolated SSID**: put the host
   there, wired if the segment has a port. Rules: segment to LAN deny, LAN to
   segment deny, segment to WAN allow. The host-side allowlist is the second
   layer.
2. **Gateway offers only a guest SSID with client isolation**: move the host
   to it. Isolation holds for wireless clients only; a wired device on the
   main LAN still cannot reach the host because the host accepts nothing
   inbound, but the control is then on the host, not outside it. Record that
   as residual.
3. **Neither**: a second, owner-owned router in front of the host with its
   WAN on the home LAN and the host as its only client; or the gateway in
   bridge mode behind an owner-owned router. The first costs one device the
   owner may already have; neither adds a service subscription.

Decoupling the admin target from the LAN address is the enabling change: bind
a stable loopback-only address as the admin target, point the private route
at it, and the host's LAN address can change (new segment, DHCP) without
touching the Cloudflare route or the laptop's SSH configuration again. That
is a route change on the account and a one-line edit in the laptop-only
operator guide; both are the owner's.

Proof, from four vantage points, recorded as evidence: a non-enrolled phone on
the home network sees no route or all ports filtered; the host cannot reach a
home device and the gateway logs the drop; a pod cannot reach the LAN; the
laptop still completes `ssh` and its route still shows the WARP interface.

## Open owner decisions

1. Delete the protected legacy archive data (the node data directory, the
   indexer directory, the wallet data) now that the daemon is retired. ADR 0013
   keeps it inert; deleting it frees most of the disk. Wallet files may be the
   only copy of keys.
2. Keep or remove the commercial WireGuard VPN egress. It predates the tunnel
   design, is a third trust party, complicated the clock-recovery incident,
   and its profile shape matches a paid tier. Recommendation: remove, with
   egress going directly through the per-service allowlist.
3. Reimage as the current LTS server image and rejoin the cluster from GitOps,
   versus continue pruning in place. Recommendation: reimage at the next LTS
   point release; it delivers the memory-safe defaults above from the
   distribution and retires the pending raspi kernel gap.
4. Reboot to activate the staged kernel command line.
5. The September validation loop mount and its LAN-bound TLS socket: the
   live sync service does not use them (its volumes sit on the root
   filesystem), but the mount holds a dataset, so deleting it is a data
   decision. The remover leaves both alone until the owner names them in
   the env file.
6. Enrolled devices: two today. The commission names the laptop and a future
   Windows PC; whether the second device stays enrolled is the owner's.
7. Remove the compilers and build tools, or keep the host a development
   environment.

## Consequences

Less code on the host, a smaller kernel surface, egress that names its
users, and evidence that a stranger can regenerate. Two residuals remain
until the owner decides: the kernel fix for two KEV-listed CVEs sits in the
distribution's proposed pocket, and the physical segment is a gateway-side
change this repository cannot make.
