# obsidian namespace capacity evidence — 2026-09-07

Evidence supporting the reviewed `namespace-budget` ResourceQuota and
`container-defaults` LimitRange for the `obsidian` namespace, the third tenant
namespace on the single-node cluster (owner ruling 2026-09-07: deploy the
obsync workload into its own namespace, named `obsidian` — the namespace is
the owner's and may later hold other Obsidian-related workloads, so this
budget is sized for the obsync Pod and must be re-derived before a second
workload joins it). The quota is bound
to these exact bytes by its `platform.snaraj.dev/capacity-evidence-sha256`
annotation, the same mechanism the two site budgets use.

Tracking issue: #348. The two-site precedent this extends: #201, recorded in
`docs/audits/2026-08-22-site-capacity-evidence.md`.

## 0. What kind of evidence this is — read this first

The 2026-08-22 site document is a MEASUREMENT: its author read node
allocatable and the cluster-wide scheduled totals off the live cluster. This
document is a DERIVATION. It reuses that measurement as its baseline and
computes a budget for a workload that has never run — snaraj/obsync has not
published v0.1.0, no image has ever been pulled, and no Pod has ever been
scheduled in this namespace. Nothing here is a live reading of obsync.

That is the honest state, and it is why the quota this document binds pays for
a workload whose HelmRelease commits `deploymentReady: false` and whose chart
selection is the all-zero placeholder digest. The budget is a CEILING reserved
ahead of a workload, not a description of one. Section 7 states exactly what
the owner must verify before that changes.

## 1. Baseline reused from the 2026-08-22 measurement

Node allocatable, read once on 2026-08-22 from the single node:

| Quantity | Capacity | Allocatable |
| --- | --- | --- |
| CPU | 4 | 3250m |
| Memory | 8127688Ki | 5506248Ki (~5377Mi) |
| Pods | — | 110 |

Safe website workload pool derived there — allocatable, less the aggregate
platform reservation, less a mandatory margin, at roughly 90% of the
remainder:

- CPU: (3250m - 1450m) x 0.9 = **1620m**
- Memory: (5377Mi - 560Mi) x 0.9 = **4335Mi**

That pool was sized for two site namespaces and the public connector. This
document spends part of the margin it left; section 6 shows how much.

## 2. Declared workload shape

Read from the application contract, not from a running Pod
(`snaraj/obsync` `chart/values.yaml`, `chart/templates/deployment.yaml`,
`docs/platform-onboarding.md` item 8) and restated in the obsync
HelmRelease `snaraj/platform-k8s-infra` composes, so the quota this repository
owns and the Pod it pays for stay one reviewable pair across the two:

| Fact | Value |
| --- | --- |
| Replicas | 1 |
| Rollout strategy | `Recreate` |
| Per-Pod requests | `cpu=100m`, `memory=64Mi` |
| Per-Pod limits | `cpu=2`, `memory=1Gi` |
| Volumes | 2 x `ReadWriteOnce` (`local-pie-ssd`) |

Three constraints follow, and all three are load-bearing for section 3.

**Two Pods can never run at once.** The blob and journal volumes are
`ReadWriteOnce` and the journal has exactly one writer, so a second Pod could
neither bind them nor be allowed to. `Recreate` is the only correct rollout
here, not a tuning preference, and there is no surge slot to pay for.

**A Pod ceiling of one nevertheless reproduces #198.** Under `Recreate` the
Deployment waits for the old Pod to be deleted before creating the new one, so
the steady path needs one slot. A Pod stuck `Terminating` — a finalizer, node
pressure, a wedged mount — still occupies its quota slot, and at a ceiling of
one its replacement is then denied by quota with no retry able to recover it.
That is the same shape that permanently wedged a site's Helm release history.
The ceiling is therefore two: the terminating slot plus its replacement, which
doubles as the slot an operator debug Pod would need.

**The ceiling must scale with the Pod ceiling.** Raising `pods` while leaving
`limits.memory` at one Pod's worth would be cosmetic — the second Pod could not
schedule whatever `pods` said. This is the exact error the 2026-08-22 review
found in the pre-#201 site budget, so every quantity below is the Pod ceiling
times the per-Pod figure.

## 3. Reviewed budget

| Key | Value | Derivation |
| --- | --- | --- |
| `pods` | `2` | terminating slot + replacement |
| `requests.cpu` | `200m` | 2 x 100m |
| `requests.memory` | `128Mi` | 2 x 64Mi |
| `limits.cpu` | `4000m` | 2 x 2 cores |
| `limits.memory` | `2Gi` | 2 x 1Gi |

The `container-defaults` LimitRange states the same per-Pod envelope as its
`default`/`defaultRequest` pair, so a container that omitted its resources
would be admitted at exactly the figures this budget was derived from rather
than at a number nobody reviewed.

## 4. Why this namespace does not reuse the site map

`docs/audits/2026-08-22-site-capacity-evidence.md` fixes one five-value map for
both site namespaces because both run the identical workload: two replicas of a
stateless Go web server at 25m/32Mi requests and 200m/128Mi limits. obsync
runs one stateful single-writer server whose per-Pod limit is ten times the
site figure on CPU and eight times on memory. One shared map could not state
both honestly: sized for the sites it would refuse the obsync Pod outright,
and sized for obsync it would hand each site four times the ceiling its own
evidence supports.

The three checks that bind these budgets — `scripts/validate_repository.py`,
`policies/conftest/kubernetes.rego` and
`policies/release-conftest/deployment-readiness.rego` — therefore move from one
map to one map PER NAMESPACE, each still exact and each still bound to its own
evidence document's bytes. No namespace loses a check: a namespace with no
entry has no admissible budget at all.

## 5. Storage is NOT reviewed by this document

The two `ReadWriteOnce` volumes (250 GiB blobs, 4 GiB journal on
`local-pie-ssd`) are outside a ResourceQuota's scope and outside this
evidence. `docs/runbooks/storage-admission.md` is explicit that permanent
PersistentVolume, StorageClass and host preparation stay bootstrap/operator
owned, and that this repository must not claim storage activation until the
ADR 0012 evidence exists — a local physical block device, reviewed filesystem
and capacity, UUID-bound mount with `nodev,nosuid,noexec`, no symlink, bind,
nested, network, loop, iSCSI or NBD escape, backup and restore drills,
preserved SSH and control-plane headroom, exact PV/PVC binding, and live
cross-namespace denial tests. That evidence does not exist, so this namespace's
storage remains a NO-GO regardless of the quota above.

## 6. Check against the safe pool

Scheduling is governed by requests, so the requests rows are what must stay
inside section 1's pool. Combined ceilings across all four namespaces — not
current scheduled totals:

| Quantity | naranjo-online | lidersea-com | cloudflare-public | obsidian | Total | Safe pool | Utilisation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `requests.cpu` | 150m | 150m | 500m | 200m | 1000m | 1620m | 62% |
| `requests.memory` | 192Mi | 192Mi | 512Mi | 128Mi | 1024Mi | 4335Mi | 24% |

Both stay inside the reviewed pool with margin. CPU is the tighter of the two
and is the number to re-check before any further namespace is added: 62% of
the pool is committed and a second workload of this size would take it past
80%.

Limits are the deliberately looser half and already overcommit, as the
2026-08-22 document records and explains. Adding this namespace's `limits.cpu`
ceiling of 4000m to that document's 6400m projection gives 10400m against
3250m allocatable (~320%). Limits are ceilings, not reservations, and only
requests participate in scheduling — but 320% is a materially different posture
from the ~197% the owner reviewed in August, and section 7 names it as
something to accept explicitly rather than inherit silently.

## 7. What the owner must verify before this budget becomes live

This document is a derivation from an August measurement plus a declared
envelope. Each item below is owner-owed and none is discharged here:

1. **Re-measure the node.** Read allocatable and the cluster-wide scheduled
   requests and limits again. The 2026-08-22 figures are a point-in-time
   reading and this change adds a namespace, which that document names as
   exactly the kind of material change that warrants re-measuring.
2. **Accept the limits overcommit.** Confirm that ~320% of allocatable in CPU
   limits across four namespaces is the intended posture on a single node, or
   direct a lower `limits.cpu` for this namespace.
3. **Confirm the per-Pod envelope against a real run.** 100m/64Mi requests and
   2 cores/1Gi limits are the application repository's declared figures for a
   workload that has never run on this hardware. The first live release is the
   first opportunity to measure steady-state and scrub-time consumption; a
   material difference is a reason to re-cut this document, never to widen the
   quota quietly.
4. **Provision the storage under the ADR 0012 evidence**, or accept that this
   namespace stays at `deploymentReady: false` indefinitely. Section 5 is not
   a formality: without a bound PersistentVolume the Pod stays `Pending` and
   the quota above is reserving capacity nothing can use.
5. **Confirm the Pod ceiling of two** is the intended trade. It costs one
   Pod slot of headroom to remove a wedge class that has already cost this
   cluster one permanently stuck release.

## 8. What this evidence does not establish

- **No high availability.** One replica on one node. A node, disk, ISP,
  Tunnel or control-plane failure takes the workload down, and this budget
  does not change that.
- **No durability claim.** A single copy without backups is an accepted risk
  the application repository records; nothing here reviews it.
- **No production-graduation decision.** Graduating this workload under
  ADR 0014 is a separate owner decision and `release-policy.env` is untouched.
- **Not a measurement of obsync.** Section 0 says it plainly and it is the
  single most important sentence in this document.

- Fable5.1
