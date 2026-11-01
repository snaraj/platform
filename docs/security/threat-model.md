# Threat model

## Assets and assumptions

Protected assets include GitHub/Cloudflare control planes, the Pi and SSD,
irreplaceable media originals and publication metadata, desired state, protected
backup keys, tunnel tokens, Kubernetes PKI/API-encryption keys, user traffic, and
domain renewal continuity. The Internet, public repository
readers, pull requests, container images, the home network, and compromised
workloads are untrusted. The operator
laptop is trusted only while patched, strongly authenticated, and physically
controlled.

## Critical threats and controls

| Threat | Prevent | Detect | Recover |
| --- | --- | --- | --- |
| GitHub takeover or malicious merge | Passkey/MFA, protected main, least privilege, signed review path | audit log, CI, Flux revision | revoke sessions, revert commit, rotate affected values |
| Compromised Action/PR | full-SHA pins, read-only PR token, no infra secrets, GitHub runners | dependency review, action policy, CodeQL/scans | pin/revert, invalidate artifacts |
| Flux privilege escalation | explicit SAs, no cross-namespace refs/remote bases, no Git credential or decryption identity | RBAC/policy tests, audit metadata | suspend/revert, rotate any exposed runtime credentials |
| Stolen recovery key or private operational data | protected operator storage and encrypted off-device backups, never Git/CI | access evidence, integrity checks, exact-index/history gates | replace compromised keys, re-encrypt retained archives, rotate exposed credentials; treat topology disclosure as permanent |
| Tunnel token leak or wrong-Tunnel substitution | tunnel-specific token created on the cluster, never in Git, no API token, separate tunnels, independent account/Tunnel-ID digests | protected MAC/plaintext-identity proof, active systemd credential equality/redaction, connector inventory | revoke/rotate one tunnel, force-disconnect on compromise, verify the other unchanged |
| Stolen Pi/SSD | disk/physical controls, Kubernetes API encryption at rest | inventory/availability alert | revoke tokens/keys, rebuild, restore tested backup |
| Accidental legacy workload reactivation | separate must-inactive unit contract, every activation edge disabled, no installer/update/restore path | indexed unit active/enabled checks plus process/listener and reboot evidence | suspend platform mutation, restore hash-bound inactive state without starting the workload |
| Legacy wallet, anonymity identity, or topology disclosure | no content in Git/chat/catalog, operator encryption and separate off-device restore proof, minimized indexed diagnostics | repository privacy tests and owner-reported restore result | isolate host, revoke/rotate affected network credentials or identities where possible, reassess archive trust |
| Legacy archive overwrite or Kubernetes exposure | dedicated canonical private root, mount binding, no PV/hostPath/Flux/CI authority, excluded capacity | local contract validator, rendered-manifest and repository policy checks | stop workloads, preserve evidence, restore only to isolated storage after integrity review |
| Compromised website | restricted pod, digest/signature, no token/egress, default deny | runtime/events/Tunnel logs | roll back digest, isolate namespace, rebuild |
| Cross-site coupling as the site count grows (a connector, token, origin, chart, image or reconciler of one site serving another) | one identity tuple per site; per-instance token derivation; double-pinned connector egress and site ingress; per-namespace Rego tables keyed by every site | per-site allow/deny fixtures for every table, mutation runs, edge-probe pairwise distinctness | revoke the one affected Tunnel, roll back that site's digest; the other sites keep serving |
| Media traversal, link, or mount-boundary escape | traversal-resistant rooted opens, regular-file/segment/link checks, read-only derivative-only mount, pending bind-mount acceptance | focused malformed-path/symlink/hard-link tests plus mount-boundary audit | suspend route, preserve volume read-only, roll back digest and inspect publication boundary |
| Malicious or partial media publication | protected operator path, checksum verification, same-filesystem atomic rename, no public upload API | manifest/checksum comparison and unreachable staging tests | remove unpublished derivative, regenerate from verified original |
| Media corruption or data-volume loss | originals separated from derivatives, encrypted off-device originals/metadata backup | scheduled checksum sampling, filesystem health, timed restore drill | restore originals/metadata and regenerate delivery derivatives; etcd is not a media backup |
| Media fills root/control-plane storage | repository-wide size/magic/aggregate gates, narrow Flux artifacts, capped OCI app layer, separate reviewed data filesystem, no container writes | CI negative tests, source-controller/OCI size evidence, filesystem alerts, kubelet DiskPressure, root/data mount verification | block publication, suspend public load, retain SSH/admin path; never delete originals automatically |
| Public load starves administration | measured system/Kubernetes reserves, workload limits, bounded-memory serving, host-level admin Tunnel | CPU/memory/disk/network saturation acceptance | suspend public Tunnel/workloads while host SSH and API recovery remain available |
| Direct-origin bypass | no forwarding/listeners/DNS origin, outbound Tunnel | external port scan and DNS audit | remove exposure/firewall rule, rotate if needed |
| Unsigned image substitution | exact chart digest plus Flux cosign verification bound to protected-main publisher; digest-only workload | CI hostile source/image fixtures and live SourceVerified status | block selection, review an exact prior digest, investigate publisher |
| Accidental Flux prune | scoped paths/SAs, review, health checks | Flux events/diff | Git revert; restore persistent data separately |
| kubeadm/stacked-etcd loss | SSD preflight, compatible pins, snapshots, protected PKI/encryption backup | snapshot, certificate-expiry, and disk-health checks | compatible-version restore drill then reconcile Git |
| Host-network conflict | discovery-gated CNI/kube-proxy, conflict-free CIDRs, no automatic firewall/VPN edits | route, nftables/iptables, VPN/tunnel-interface, policy-routing, and connectivity tests | retain LAN/physical access; restore reviewed host/network state |
| Cloudflare takeover | passkey/MFA, minimal admins, short-lived scoped tokens and separate application identities | audit log, token-policy/revocation receipts, read-only inventory | revoke, recover each Tunnel and DNS identity from reviewed private evidence |
| Paid feature activation | strict resource/product allowlist, no Billing Write, explicit owner approval | pre/post subscription audit and budget alert | stop change, preserve evidence, disable if safe, dispute/escalate |

## Acceptance

Each critical threat has prevention, detection, and recovery. The proposed media
volume remains disabled until ADR 0012's discovery and recovery evidence exists.
A new public route, API, identity system, database, persistent volume, operator,
cluster, or paid exception reopens this model. Residual single-node and ISP
outage risk is accepted.

## Third public website (2026-11-01)

The owner's 2026-11-01 commission adds `hospedajedonlolo.com`, a static
bilingual brochure site, as a new public route. As the acceptance clause
above requires, the model is reopened for it. The conclusion is that it adds
no new threat class. It is a third instance of the website row: a
single-owner, trusted workload with the same chart shape, the same
restricted Pod, digest and signature controls, no token, egress denied, and
default deny. It has its own Tunnel, token, zone, namespace, budget,
reconciler and publisher identity, so it shares no edge or reconciliation
object with the other sites. The cross-site coupling row above is the control
that grows with the site count.

Two facts are recorded here, not decided:

- **Read-only media.** The site mounts one operator-provisioned, read-only
  claim. The claim and its volume are created outside Git, and the site's
  Helm account has no claim verbs. A compromised site Pod can read that media
  and cannot write it.
- **Large media through the edge.** The site serves one roughly 20 MB video
  through the proxied edge, as naranjo.online already serves films. The open
  provider-terms question recorded in
  [ADR 0006](../adr/0006-cloudflare-zero-spend.md) and its 2026-11-01
  amendment applies to both sites. The owner decides it.
