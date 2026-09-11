# obsync workload onboarding — reviewable proposal

Dated 2026-09-07. Tracking issue: #348. Owner directive of the same date:
deploy the obsync application into the homelab in its own namespace, `obsidian`.

This document is the REVIEWABLE PROPOSAL for the parts of that onboarding this
repository must not write itself. Everything it proposes is stated in full —
ADR amendment text, transport design, the storage ceremony — so the owner or
the platform lane can act on it without reconstructing anything. Nothing here
is applied by any tool.

**Two repositories, and the split is load-bearing.** Since the application
composition was extracted, `platform` (this repository) owns the namespace and
its Pod Security labels, the hash-bound budget and LimitRange, the reconciler
and Helm RBAC in `kubernetes/flux-system/access.yaml`, and the Tunnel
connector under `kubernetes/platform/cloudflare-public/`. It owns WHO may act.
`platform-k8s-infra` owns the four composition manifests — default-deny,
`OCIRepository`, `HelmRelease`, `kustomization` — under
`kubernetes/websites/obsync/`. It owns WHAT is applied. Neither half deploys
anything on its own, and every row of section 4 names which repository carries
it.

## 0. The identity tuple, once, so nothing below re-derives it

| Fact | Value |
| --- | --- |
| Application repository | `snaraj/obsync` |
| Image | `ghcr.io/snaraj/obsync` |
| Chart | `oci://ghcr.io/snaraj/charts/obsync` |
| Publisher identity | `https://github.com/snaraj/obsync/.github/workflows/release-publisher.yml@refs/heads/main` |
| Namespace | `obsidian` — the OWNER's namespace, not the application's |
| Flux release / reconciler | `obsync` / `obsync-reconciler`, both in `obsidian` |
| Chart source object | `obsync-chart` |
| Composition repository | `snaraj/platform-k8s-infra`, `kubernetes/websites/obsync/` |
| Tunnel connector instance | `obsync-tunnel` |
| Token Secret name | `obsync-tunnel-token` |
| Server-key Secret | `obsync-server-key`, key `OBSYNC_SERVER_KEY` |
| Reachability | the owner's private WARP network only. No public hostname, no public DNS record, no Access application in front of a public origin. `publicUrl` is the empty string: the name lives in operator inputs, never in Git |
| First release | v0.1.0, not yet published |

**Everything the APPLICATION owns is `obsync` or starts with `obsync`; the
NAMESPACE it lives in is `obsidian`, and the split is the owner's ruling of
2026-09-07 rather than an accident.** The namespace is named for the owner's
tooling and may later hold other Obsidian-related workloads that are not
obsync. Every object inside it that belongs to this application therefore
carries the application's name — reconciler, chart source, Flux release,
connector instance, both Secrets, both volumes, the ServiceAccount — so a
second workload admitted to that namespace later would not collide with any of
them by NAME.

**That is a naming property and not an isolation property, and the difference
matters enough to state twice.** Review of this branch made the point exactly:
naming everything `obsync` says nothing about what a co-resident workload could
reach. The namespace holds ONE reviewed workload today, and co-residency is a
future TRUST DECISION rather than something these names already secure. This
design does not build a multi-tenant admission boundary and does not claim one.

What it does do is refuse to leave the authority generic while saying otherwise.
The Helm account in this namespace is `obsync-helm-reconciler`, not the shared
`helm-reconciler` the two sites use, and its Role separates creation — which
cannot carry `resourceNames` because the object does not exist yet — from every
follow-up mutation, which is pinned to the chart's rendered names (`obsync`,
`obsync-blobs`, `obsync-journal`). There is no namespace-wide claim rule. One
grant stays namespace-wide and is named rather than buried: Helm's release
storage is version-suffixed (`sh.helm.release.v1.obsync.v1`, `.v2`, ...), so
those Secret names cannot be known ahead of the releases that produce them.
Admitting a second workload here would have to answer for exactly that grant.

The practical consequence for a reviewer, and for every validator in this
change: NOTHING in the `obsidian` namespace may be derived from the namespace
name. `scripts/validate_repository.py` therefore carries
`WORKLOAD_APPLICATIONS` (namespace to application) and builds
`<application>-reconciler`, `<application>-chart` and `<application>` from it,
and `policies/conftest/kubernetes.rego` carries `connector_instances`,
`origin_app_labels` and `site_workload_accounts` as per-namespace TABLES for
the same reason. The two sites still happen to be one word throughout, and the
tables state that as a fact rather than assuming it as a rule.

The one identity in this design that is deliberately NOT the application is
the connector's origin, and it is not a naming exception — it is the transport
decision of section 1. The obsync server speaks plain HTTP, so TLS terminates
in-cluster in a dedicated proxy workload (`obsync-tls-proxy`, a separate
platform workload, never a sidecar). The admitted edges are:

- connector to proxy, on the proxy's TLS port;
- proxy to application, on the application's HTTP port
  (`obsync.obsidian.svc.cluster.local:8080` — the chart's
  `templates/service.yaml` names the Service `obsync`);
- and NO connector-to-application edge in any contributing policy.

The proxy's exact identity arrives with the security lane's own reviewed
deployment change. Until then both halves of the binding — the connector's
egress leg in this repository and the application's ingress peer in the
composition — name the declared placeholder `obsync-tls-proxy` /
`obsync-tls-proxy-pending`, which no Pod carries. That selects nothing and
fails CLOSED, which is the correct interim state: binding the connector
straight to the application "temporarily" would have been a route that works
and should not.

## 1. Proposed ADR 0015 revision (Cloudflare/edge lane)

ADR 0015 admits exactly two per-site Tunnels, both public. The proposal below
is a third Tunnel of a DIFFERENT shape: private. It is written as an
append-only `## Amendment` section, the convention ADRs 0010, 0014, 0015 and
0016 already use, so every pre-existing line stays byte for byte intact and
what it corrects it corrects on the record.

Lane note, and it matters for who applies this: AGENTS.md's owner lane re-cut
of 2026-08-12 assigns the Cloudflare ADRs — "0006–0008, 0015, and successors"
— to the DELIVERY lane, so ADR 0015 is a file that lane may edit. The
commission for issue #348 nevertheless directed that no `docs/adr/**` file be
touched on this branch, so the text is proposed here rather than applied.

### Proposed text, verbatim

> ## Amendment (2026-09-07) — a third Tunnel, private rather than public
>
> The decision above admits exactly two Tunnels because two PUBLIC websites
> existed and each needed one public hostname. The owner's ruling of
> 2026-09-07 adds a third workload, `obsync` (the obsync live-sync server),
> to the same cluster. It is not public content: it is a personal sync server
> whose dashboard is an administrative surface and whose `/v1/*` API is what
> the Obsidian plugin and the mobile client speak. This section extends the
> decision to it and changes nothing about the two sites; every prior line
> stands.
>
> The third Tunnel shares no object, token, DNS record or failure domain with
> either site, and differs from both in the property that matters:
>
> 1. **No public hostname and no public DNS record.** The Tunnel publishes a
>    PRIVATE network route reachable only from the owner's WARP-enrolled
>    devices. There is no proxied CNAME, no zone entry, and therefore no
>    shared-zone edge coupling with either site at all — the one isolation gap
>    a third public hostname would have carried is absent by construction.
> 2. **No public hostname rule and no terminal `http_status:404` rule.** Those
>    exist to bound what a public ingress rule set exposes; a Tunnel with no
>    public ingress has nothing for them to bound.
> 3. **Reachability is enrolment, not a URL.** A device that is not enrolled in
>    the owner's WARP network cannot resolve or route to this workload at all.
>    An unenrolled attacker has no endpoint to attack, which is a stronger
>    property than any policy evaluated after a request arrives.
>
> Its runtime credential is its own: one token, held only as a Kubernetes
> Secret (`obsync-tunnel-token`), never a literal manifest value, and rotated
> independently of the two sites. It reaches the connector as a FILE, not an
> environment variable: the chart projects the Secret as a read-only volume at
> mode `0440` and passes `--token-file /etc/cloudflared/token/token`. That is
> the shape the chart actually renders, and the difference is not cosmetic — an
> environment variable is readable from `/proc/<pid>/environ` by anything that
> can see the process and is copied into every child, while a projected file is
> read once at the path the argument names.
>
> No new zone and no new Cloudflare product: WARP and Tunnel are both already
> in the committed allowlist and both are Free-tier, so the zero-spend posture
> of safety invariant 4 and ADR 0006 is untouched.
>
> ### Where identity is proven
>
> A public Access application in front of a public hostname is what the two
> sites would need and this workload does not have. Device enrolment in the
> owner's WARP network is the edge identity gate here, and the Access device
> enrolment policy that governs it already exists — it is the same one that
> admits this laptop. No Access application, no service token and no
> `CF-Access-Client-*` header pair is introduced.
>
> That is not a substitute for the application's own authentication: the
> server still authenticates every device itself, and it is told nothing by
> the transport that it trusts.
>
> ### TLS terminates in the cluster, not at the edge
>
> The two sites terminate TLS at Cloudflare's edge because their traffic
> arrives over the public Internet. This workload's traffic never does: it
> travels the WARP tunnel from an enrolled device to `cloudflared` and is
> handed to an origin inside the cluster's own default-deny boundary. TLS
> therefore terminates in-cluster, in a dedicated proxy workload rather than at
> the edge: the connector's origin is that proxy, over TLS, and the proxy
> reaches the application over plain HTTP on the same reasoning recorded above
> for the sites' last hop. There is no connector-to-application leg.
>
> HSTS ownership is unchanged and is the application's. No Ingress, Gateway,
> NodePort, LoadBalancer or origin A/AAAA record is introduced (ADR 0008,
> safety invariant 3), and none is needed: a private route is not an ingress
> object.

### The three values the transport decision reaches

This is where the decision above stops being prose and becomes data, and each
value is worth stating plainly because the wrong one fails CLOSED but totally.

**`edge.mode: none`.** The obsync chart's `edge.mode` selects what the server
demands of whatever is in front of it. `cloudflare` makes it REQUIRE the
edge's connecting-address and request-id headers on every request and refuse
requests that lack them. Those headers are added by Cloudflare's HTTP edge on
a PUBLIC hostname path. A private WARP route does not traverse that edge, so
they are never set — and a server configured for `cloudflare` would refuse
every single request from the owner's own laptop.

**`trustedProxyCidrs: []`.** Empty is the strict setting rather than the lazy
one: in `none` mode the server believes a forwarded address only from a listed
range, so an empty list means it believes only the peer address — the
in-cluster TLS proxy of section 0, the sole ingress path the default-deny
policy admits.
Naming a CIDR there would make an `X-Forwarded-For` header believable from
anything in that range.

**`publicUrl: ""`.** NOT a sentinel hostname. The chart's closed schema admits
the empty string and the application treats an unset public URL as unset: the
pairing page shows none and a device is given the address by the person
setting it up. That keeps the owner's private name out of public Git
permanently — safety invariant 12 treats the index as public, and a
placeholder hostname is a habit of carrying the real one later. The private
name and the private route's address live only in operator inputs.

`ingress.peerNamespace`, `ingress.peerAppName` and `ingress.peerInstance` name
the in-cluster TLS proxy of section 0 and never the connector, in the declared
placeholder form (`obsync-tls-proxy` / `obsync-tls-proxy-pending`) that no Pod
carries. The rendered ingress policy therefore admits nothing until the
security lane's own reviewed deployment supplies the proxy's real identity in
the same change. That is the correct interim state: an absent proxy is a route
that does not work, and naming the connector "temporarily" would have been a
route that works and should not.

The composition in `platform-k8s-infra` states all four in the obsync
`HelmRelease`, and its manifest-shape policy pins those bytes.

## 2. Cloudflare-side ceremony (owner)

None of this is in Git and none of it can be. In order:

1. Create the Tunnel named for this workload's tuple; record its identifier in
   local custody, not here.
2. Add ONE private network route on that Tunnel covering the origin the
   connector reaches. Create no public hostname rule, no DNS record and no
   Access application for a public origin.
3. Confirm the enrolled devices that may reach it are exactly the ones the
   existing WARP device enrolment policy admits.
4. Create the connector token Secret on the cluster
   (`obsync-tunnel-token`, key `token`) and, in the same reviewed pull
   request, move this workload's `tokenRevision` in
   `kubernetes/platform/cloudflare-public/release/release.yaml` from
   `not-configured` to its `rev-…` value. The other two connectors are
   untouched by that edit, which is the whole reason the revisions are per
   connector.

Until step 4 lands, the connector release stays suspended and this repository
refuses to claim an activated state. That is the intended sequencing, not an
obstacle to route around.

## 3. Storage: why no PersistentVolume is committed in either repository

The commission asked for a `storage.yaml` carrying two static local
PersistentVolumes. It is deliberately absent from both repositories, for
reasons each states itself:

1. `scripts/validate_repository.py` FORBIDS the kinds outright in this
   repository. Its `check_kubernetes` sweep over every live Kubernetes file
   denies `PersistentVolume`, `PersistentVolumeClaim` and `StorageClass` as a
   "persistent storage object", and `kubernetes/**` carries none today —
   naranjo-online's usage-export claims bind to volumes an operator created
   out of band.
2. `platform-k8s-infra`'s contract says the same in one line: "Reject public
   Kubernetes entry points, host networking, storage activation, unknown
   resources, cross-namespace references and arbitrary Helm values."
3. A `local` PersistentVolume requires a bounded `required` nodeAffinity
   naming the node. The node identity is a discovery fact ADR 0012 and safety
   invariant 12 keep out of the index: the repository's own model fixture,
   `tests/kubernetes/fixtures/allow/storage-enumerated-local.yaml`, uses the
   placeholder `storage-node-placeholder` and says why. Committing a real node
   name would publish a host identity permanently; committing the placeholder
   would commit desired state that binds nothing.
4. `docs/runbooks/storage-admission.md` is explicit: "Permanent PV/StorageClass
   and host preparation stay bootstrap/operator owned; tenant reconciliation
   cannot create, retarget, delete, or widen them." The obsync reconciler's
   RBAC is namespace-scoped by design and PersistentVolume is cluster-scoped,
   so applying one from this Kustomization would need a new cluster-scoped
   grant — an authority-boundary change, not an onboarding detail.

The chart creates the CLAIMS (`obsync-blobs`, `obsync-journal` — the chart's
own names, not `obsync-*`). The volumes are the operator ceremony below.

### Physical-profile operator ceremony, for the platform lane to apply directly

Substitute the real node name at apply time; it is never committed.

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: obsync-blobs
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
    path: /mnt/local-pie-ssd/obsidian/obsync-blobs
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
  name: obsync-journal
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
    path: /mnt/local-pie-ssd/obsidian/obsync-journal
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

The reserved-file alternative uses the separate exact identities in
[ADR 0017](../adr/0017-reserved-file-storage.md) and its
[qualification procedure](../runbooks/reserved-file-storage.md). Do not retarget
these physical-profile objects or a bound claim by editing a class name.

**None of this is authorized by this document.** ADR 0012's physical-profile activation
evidence — a local physical block device, reviewed filesystem and capacity, a
UUID-bound mount with `nodev,nosuid,noexec`, no symlink/bind/nested/network/
loop/iSCSI/NBD escape, backup and restore drills, preserved SSH and
control-plane headroom, exact PV/PVC binding, and live cross-namespace denial
tests — does not exist, and until it does this namespace's storage is a NO-GO
regardless of what the quota says. The reserved profile has its own mandatory
evidence and remains disabled until that independent qualification passes.

## 4. What is landed, and where

In THIS repository (`platform`): the namespace and its restricted Pod Security
labels, the hash-bound quota and LimitRange with their own evidence document
(`docs/audits/2026-09-07-obsync-capacity-evidence.md`), the reconciler
identity and impersonation authority, the Helm reconciler Role including its
claim-lifecycle rule, the third connector in the `cloudflare-public` chart with
its own origin-egress policy and its own token revision, the widened Conftest
tenant/chart-source/budget sets, and the hostile negative controls for all of
it.

In `platform-k8s-infra`: the four composition manifests under
`kubernetes/websites/obsync/`, the pending-application declaration that
admits them without inserting a third ACTIVE application, and the negative
tests for that declaration.

Not landed, and each needs the named actor:

| Item | Actor | Blocked on |
| --- | --- | --- |
| ADR 0015 amendment (section 1) | delivery lane, next PR | nothing — text is above |
| Tunnel and private network route (section 2) | owner | nothing |
| `obsync-tunnel-token` Secret + `tokenRevision` move | owner, then a reviewed PR | the Tunnel existing |
| `obsync-server-key` Secret | owner | nothing |
| Two PersistentVolumes and the host directories (section 3) | platform lane / owner | ADR 0012 activation evidence |
| Pod-volume policy narrowing to admit the two claims | security lane | an owner decision on the narrowing |
| Real chart digest in the composition's `source.yaml` | coordinator | snaraj/obsync v0.1.0 Release |
| Receipt-contract closure for a third identity tuple, in BOTH repositories | delivery lane, security tier | the same v0.1.0 Release |
| `deploymentReady: true` and resuming the release | delivery lane | every row above |
| Live-evidence vocabulary for a staged workload (section 5) | owner, then delivery lane | a ruling on what a staged workload owes a live capture |

## 5. Consequences a reviewer should expect to see, not be surprised by

- **The receipt closure is now doubled, and both halves refuse a third tuple.**
  In this repository, `scripts/ci/platform_release_contract.py` requires the
  chart acquisition receipt to bind EXACTLY the two site identities —
  `set(records) != set(expected_sites)` is a hard refusal. In
  `platform-k8s-infra`, `scripts/validate.py` requires
  `set(receipt["records"]) == set(APPLICATIONS)` on the same terms. A receipt
  record states the exact manifest digest, layer digest, config digest, arm64
  digest, Release asset digest and source SHA that an acquisition ceremony
  RESOLVED, and none of those exist for a release that has not been published.
  Both closures therefore move in the SAME reviewed change as the first real
  digest, and neither may be pre-opened to reserve a place.
- **Two live-evidence validators still describe a two-workload cluster.**
  `scripts/validate_flux_release_evidence.py` gained this workload's
  Kustomization, because that object exists live the moment the entry merges.
  It deliberately did NOT gain the OCIRepository, HelmRelease or HelmChart
  inventories: those require a `SourceVerified` source and a Ready release with
  a deployed history, which a placeholder digest and a suspended release can
  never produce. The contract has no vocabulary for "reconciled but staged",
  and inventing one inside a live-evidence check is an owner decision.
  `scripts/validate_runtime_inventory_evidence.py` has the same shape and is
  untouched: its Namespace, Deployment and Service inventories still name two
  workloads. Neither is on the `make check` path and neither is failing, but
  both will describe the cluster incorrectly at the next live capture — the
  Namespace list from the moment the owner applies `namespaces.yaml`, the rest
  only once this workload actually deploys.
- **The Pod-volume policy does not admit a claim.** The platform's
  workload-volume control (`policies/conftest/kubernetes.rego`,
  `admitted_pod_volume_sources`) admits only `emptyDir`, `configMap`, `secret`,
  `projected` and `downwardAPI`, so the obsync Pod's two claim volumes would be
  denied if either repository ever rendered that Deployment. Neither does — the
  chart is remote and arrives through a signature-verified OCIRepository, as
  both site charts do — but the naranjo-online usage-export claims are in the
  same position, and the gap is an owner and security-lane decision rather than
  a silence. The proposed narrowing is stated in the `platform-k8s-infra` pull
  request: admit `persistentVolumeClaim` ONLY in the `obsync` application and
  ONLY for the two named claims, never as a general source.

- Fable5.1
