# Obsidian workload onboarding — reviewable proposal

Dated 2026-09-07. Tracking issue: #348. Owner directive of the same date:
deploy the obsync application into its own namespace in the homelab, namespace
`obsidian`.

This document is the REVIEWABLE PROPOSAL for the parts of that onboarding this
lane must not write itself. Everything it proposes is stated in full — ADR
amendment text, Cloudflare Access design, the storage ceremony — so the owner
or the platform lane can act on it without reconstructing anything. Nothing
here is applied by any tool; the branch that carries this document changes only
delivery-lane paths and the declared crossings named in its pull-request body.

## 0. The identity tuple, once, so nothing below re-derives it

| Fact | Value |
| --- | --- |
| Application repository | `snaraj/obsync` |
| Image | `ghcr.io/snaraj/obsync` |
| Chart | `oci://ghcr.io/snaraj/charts/obsync` |
| Publisher identity | `https://github.com/snaraj/obsync/.github/workflows/release-publisher.yml@refs/heads/main` |
| Namespace | `obsidian` |
| Flux release / reconciler | `obsidian` / `obsidian-reconciler` |
| Chart source object | `obsidian-chart` |
| Tunnel connector instance | `obsidian-tunnel` |
| Token Secret name | `obsidian-tunnel-token` |
| Server-key Secret | `obsidian-server-key`, key `OBSYNC_SERVER_KEY` |
| Public hostname | `obsidian.naranjo.online` |
| First release | v0.1.0, not yet published |

**The halves are deliberately different words, and this is the single most
load-bearing fact in this document.** The two websites are named for their
domains all the way down, so every part of their tuple is one word and every
selector built from any part of it happens to be correct. obsync is not: the
platform names the namespace, the Flux release and the reconciler `obsidian`,
while the application repository names the chart, the image, the Helm app name,
the Service and the ServiceAccount `obsync`. Two consequences follow that a
reviewer should check first, because both look correct and behave wrong:

- The connector's origin selector must be
  `app.kubernetes.io/name: obsync`, not `obsidian`. The obsync chart hardcodes
  `obsync` as its app name; a selector built from the namespace name selects
  no Pod, so the connector reaches no origin and the failure is a policy that
  reads right and silently routes nowhere.
- The in-cluster origin is `http://obsync.obsidian.svc.cluster.local:8080`,
  not `http://obsidian.obsidian.svc.cluster.local:8080`. The chart's
  `templates/service.yaml` names the Service `obsync`. The commissioning brief
  for this work stated the latter; it is corrected here and in the ADR text
  below.

## 1. Proposed ADR 0015 revision (platform/Cloudflare lane)

ADR 0015 admits exactly two per-site Tunnels. The proposal below is a third
per-app Tunnel of the same shape. It is written as an append-only `##
Amendment` section, the convention ADRs 0010, 0014, 0015 and 0016 already use,
so every pre-existing line stays byte for byte intact and what it corrects it
corrects on the record.

Lane note, and it matters for who applies this: AGENTS.md's owner lane re-cut
of 2026-08-12 assigns the Cloudflare ADRs — "0006–0008, 0015, and successors"
— to the DELIVERY lane, so ADR 0015 is a file this lane may edit. The
commission for issue #348 nevertheless directed that no `docs/adr/**` file be
touched on this branch, so the text is proposed here rather than applied.
Folding it into ADR 0015 is a one-file follow-up for whichever lane the
coordinator assigns; it needs no new authority.

### Proposed text, verbatim

> ## Amendment (2026-09-07) — a third per-app Tunnel
>
> The decision above admits exactly two Tunnels because two websites existed.
> The owner's ruling of 2026-09-07 adds a third workload, `obsidian` (the
> obsync live-sync server), to the same cluster. This section extends the
> decision to it and changes nothing about the two sites; every prior line
> stands.
>
> The third Tunnel is identical in shape to the two above and shares no object,
> token, DNS record or failure domain with either:
>
> 1. exactly one public hostname rule — `obsidian.naranjo.online` routed to
>    `http://obsync.obsidian.svc.cluster.local:8080`. The Service name is
>    `obsync` and the namespace is `obsidian`: this workload's artifact family
>    and its namespace are deliberately different words, and the origin URL
>    states the name the chart actually renders;
> 2. a terminal `http_status:404` rule;
> 3. no private/WARP routing, no wildcard hostname, and no SSH or API hostname.
>
> The hostname is one proxied CNAME with automatic TTL on the existing
> `naranjo.online` Free zone, targeting this Tunnel's own `cfargotunnel.com`
> name. No new zone and no new Cloudflare product: the zero-spend allowlist of
> safety invariant 4 and ADR 0006 is untouched.
>
> Its runtime credential is its own: one token, held only as a Kubernetes
> Secret (`obsidian-tunnel-token`), consumed by its connector through
> `secretKeyRef` (`TUNNEL_TOKEN`), never a literal manifest value, and rotated
> independently of the two sites.
>
> A hostname on a SHARED zone is the one thing this third Tunnel does not
> isolate, and it is named rather than glossed: `obsidian.naranjo.online` sits
> in the same zone as `naranjo.online`, so a zone-level misconfiguration or a
> zone-wide edge rule reaches both. Everything below the zone — Tunnel, token,
> connector Deployment, NetworkPolicy, namespace, release, DNS record —
> remains per workload. A separate zone would isolate that last edge too and
> is not taken here: it costs a domain, which the zero-spend posture does not
> fund, and the shared-zone risk is a configuration risk rather than a
> credential one.
>
> ### Cloudflare Access in front of this hostname
>
> Unlike the two sites, this workload is not public content. It is a personal
> sync server whose dashboard is an administrative surface and whose `/v1/*`
> API is what the Obsidian plugin and the mobile client speak. One Cloudflare
> Access application (Free tier, zero spend) covers the hostname with two
> policies, and the split is the point:
>
> - **Identity policy — the dashboard paths.** One-time PIN to the owner's
>   address, on everything the Access application covers that is not `/v1/*`.
>   A human reaching the dashboard proves an identity at the edge before the
>   request reaches the connector.
> - **Service-token policy — `/v1/*`.** A device is not a person and cannot
>   answer a one-time PIN, so the API path is admitted by a service token
>   (`CF-Access-Client-Id` / `CF-Access-Client-Secret`) instead. The plugin
>   sends those headers when configured, and the pairing code can carry them
>   so a device is provisioned in one step.
>
> Neither policy is a substitute for the application's own authentication:
> Access is an edge gate in front of a server that still authenticates every
> device itself, and the server is told nothing by Access that it trusts. The
> service token is a Cloudflare credential and lives in the owner's custody
> exactly as the Tunnel tokens do; it never enters this repository.
>
> ### What does not change
>
> The connector-to-origin leg stays plain HTTP inside the default-deny
> boundary, on the same reasoning recorded above. HSTS ownership is unchanged
> and is the application's. The terminal 404 rule is unchanged. No ingress,
> Gateway, NodePort, LoadBalancer or origin A/AAAA record is introduced
> (ADR 0008, safety invariant 3).

## 2. Cloudflare-side ceremony (owner)

None of this is in Git and none of it can be. In order:

1. Create the Tunnel named for this workload's tuple; record its
   `cfargotunnel.com` name in local custody, not here.
2. Create the single hostname rule and the terminal 404 rule exactly as the
   amendment states.
3. Create the proxied CNAME for `obsidian.naranjo.online` with automatic TTL.
4. Create the Access application and its two policies.
5. Create the connector token Secret on the cluster
   (`obsidian-tunnel-token`, key `token`) and, in the same reviewed pull
   request, move this workload's `tokenRevision` in
   `kubernetes/platform/cloudflare-public/release/release.yaml` from
   `not-configured` to its `rev-…` value. The other two connectors are
   untouched by that edit, which is the whole reason the revisions are per
   connector.

Until step 5 lands, `scripts/validate_release_transition.py` classifies the
connector as `initial` and the repository refuses to claim a release. That is
the intended sequencing, not an obstacle to route around.

## 3. Storage: why no PersistentVolume is committed on this branch

The commission asked for `kubernetes/websites/obsidian/storage.yaml` carrying
two static local PersistentVolumes. It is deliberately absent, for three
reasons the repository states itself:

1. `scripts/validate_repository.py` FORBIDS the kinds outright. Its
   `check_kubernetes` sweep over every live Kubernetes file denies
   `PersistentVolume`, `PersistentVolumeClaim` and `StorageClass` as a
   "persistent storage object", and `kubernetes/**` carries none today —
   naranjo-online's usage-export claims bind to volumes an operator created
   out of band.
2. A `local` PersistentVolume requires a bounded `required` nodeAffinity
   naming the node (the storage policy's SR-6). The node identity is a
   discovery fact ADR 0012 and safety invariant 12 keep out of the index: the
   repository's own model fixture,
   `tests/kubernetes/fixtures/allow/storage-enumerated-local.yaml`, uses the
   placeholder `storage-node-placeholder` and says why. Committing a real node
   name would publish a host identity permanently; committing the placeholder
   would commit desired state that binds nothing.
3. `docs/runbooks/storage-admission.md` is explicit: "Permanent PV/StorageClass
   and host preparation stay bootstrap/operator owned; tenant reconciliation
   cannot create, retarget, delete, or widen them." The obsidian reconciler's
   RBAC is namespace-scoped by design and PersistentVolume is cluster-scoped,
   so applying one from this Kustomization would need a new cluster-scoped
   grant — an authority-boundary change, not an onboarding detail.

The chart creates the CLAIMS (`obsync-blobs`, `obsync-journal` — the chart's
own names, not `obsidian-*`; the application repository's `docs/storage.md`
says `obsidian-blobs`/`obsidian-journal` and its own `chart/templates/storage.yaml`
disagrees, which that repository should reconcile). The volumes are the
operator ceremony below.

### Proposed operator ceremony, for the platform lane to apply directly

Substitute the real node name at apply time; it is never committed.

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: obsidian-blobs
spec:
  capacity:
    storage: 250Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: local-pie-ssd
  volumeMode: Filesystem
  claimRef:
    namespace: obsidian
    name: obsync-blobs
  local:
    path: /mnt/local-pie-ssd/obsidian/blobs
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [storage-node-placeholder]
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: obsidian-journal
spec:
  capacity:
    storage: 4Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: local-pie-ssd
  volumeMode: Filesystem
  claimRef:
    namespace: obsidian
    name: obsync-journal
  local:
    path: /mnt/local-pie-ssd/obsidian/journal
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [storage-node-placeholder]
```

`claimRef` is present on purpose: it pre-binds each volume to exactly the claim
the chart creates, so the journal volume can never be handed to the blob claim
by the scheduler's ordinary matching. `operator: In` with an explicit value is
also on purpose: `Exists` on `kubernetes.io/hostname` matches every node that
ever joins, which is the unbounded selection the storage policy exists to
refuse.

**None of this is authorized by this document.** ADR 0012's activation
evidence — a local physical block device, reviewed filesystem and capacity, a
UUID-bound mount with `nodev,nosuid,noexec`, no symlink/bind/nested/network/
loop/iSCSI/NBD escape, backup and restore drills, preserved SSH and
control-plane headroom, exact PV/PVC binding, and live cross-namespace denial
tests — does not exist, and until it does this namespace's storage is a NO-GO
regardless of what the quota says.

## 4. What this branch already does, so a reviewer knows what is left

Landed in the delivery lane on this branch: the namespace and its restricted
labels, the hash-bound quota and LimitRange with their own evidence document,
the namespace-owned default-deny, the reconciler and Helm RBAC, the direct Flux
Kustomization and the source-artifact boundary, the composition directory with
its placeholder chart selection and suspended release, the third connector in
the `cloudflare-public` chart with its own origin-egress policy, the promoter's
`obsync-release-publisher` acquisition profile, and the hostile negative
controls for all of it.

Not landed, and each needs the named actor:

| Item | Actor | Blocked on |
| --- | --- | --- |
| ADR 0015 amendment (section 1) | delivery lane, next PR | nothing — text is above |
| Tunnel, hostname, CNAME, Access application (section 2) | owner | nothing |
| `obsidian-tunnel-token` Secret + `tokenRevision` move | owner, then a reviewed PR | the Tunnel existing |
| `obsidian-server-key` Secret | owner | nothing |
| Two PersistentVolumes and the host directories (section 3) | platform lane / owner | ADR 0012 activation evidence |
| Real chart digest in `kubernetes/websites/obsidian/source.yaml` | promoter or coordinator | snaraj/obsync v0.1.0 Release |
| Receipt-contract closure for a third identity tuple | delivery lane, security tier | the same v0.1.0 Release |
| `deploymentReady: true` and resuming the release | delivery lane | every row above |

## 5. The receipt closure, and why it is not on this branch

`scripts/ci/platform_release_contract.py` binds the platform's SIGNED release
identity to the chart acquisition receipt, and it requires the receipt to bind
EXACTLY the two site identities: `set(records) != set(expected_sites)` is a
hard refusal, and the derived `sites` block of the signed identity asset is
checked the same way. Extending that closure to a third tuple therefore cannot
be done alone — the closure and the receipt record must move together, and a
receipt record states the exact manifest digest, layer digest, config digest,
arm64 digest, Release asset digest and source SHA that an acquisition ceremony
RESOLVED. None of those exist for a release that has not been published.

The fail-closed behaviour in the meantime is already correct and is now
proven by a test: `scripts/promote_releases.py` discovers the obsidian
selection, selects its profile, and refuses to write a promotion for it with
"the receipt contract does not yet bind this workload; extend the identity
closure first". Nothing invents a record.

## 6. Two consequences a reviewer should expect to see, not be surprised by

- **The deploy-assurance watchdog will open a condition.** It derives each
  workload's repository of record from the cosign subject and asks that
  repository for its latest release. `snaraj/obsync` has published none, so
  the hourly run opens `deploy-assurance[unpublished-selection/obsidian]` and
  exits red. That is the watchdog working: the committed desired state names
  an artifact whose repository publishes nothing. It clears the moment v0.1.0
  is published, and the alternative — hiding the workload from the watchdog —
  is exactly the silent drift issue #273 exists to prevent.
- **The Pod-volume policy does not admit a claim.** The platform's
  workload-volume control admits only `emptyDir`, `configMap`, `secret`,
  `projected` and `downwardAPI`, so the obsync Pod's two claim volumes would be
  denied if this repository ever rendered that Deployment. It does not — the
  chart is remote and arrives through a signature-verified OCIRepository, as
  both site charts do — but the naranjo-online usage-export claims are in the
  same position, and the gap is worth an owner decision rather than a silence.

- Fable5.1
