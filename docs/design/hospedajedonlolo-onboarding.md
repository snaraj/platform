# hospedajedonlolo.com onboarding: the operator ceremony

The owner's 2026-11-01 commission adds Hospedaje Don Lolo, a family farm-stay's
static bilingual brochure site, as the third public website (issue #422). This
repository now carries everything that decides **who may act** for it. This
document lists, in order, everything that still has to happen outside Git
before it serves. Nothing here is live authorization. Each step runs only
inside an owner-authorized operation window. The actor keeps a private journal
outside Git, and every observed value below that is not public goes into that
journal and nowhere else.

## 0. The identity tuple

Safety invariant 14 makes these one tuple. No member is derived from another
member's spelling.

| Member | Value |
| --- | --- |
| Domain and Free zone | `hospedajedonlolo.com` |
| Namespace, Helm release, workload ServiceAccount, origin Pod label | `hospedajedonlolo-com` |
| Chart source and chart | `hospedajedonlolo-com-chart`, `oci://ghcr.io/snaraj/charts/hospedajedonlolo-com` |
| Image | `ghcr.io/snaraj/hospedajedonlolo-com` |
| Publisher identity | `https://github.com/snaraj/hospedajedonlolo.com/.github/workflows/release-publisher.yml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com` |
| Reconciler and path | `hospedajedonlolo-com-reconciler`, `./kubernetes/websites/hospedajedonlolo-com` |
| Helm account | `helm-reconciler` (the generic site shape, with no claim verbs) |
| Tunnel, connector, token Secret | `hospedajedonlolo-com`, `hospedajedonlolo-com-tunnel`, `hospedajedonlolo-com-tunnel-token` |
| Origin | `http://hospedajedonlolo-com.hospedajedonlolo-com.svc.cluster.local:8080` |
| Media claim | `hospedajedonlolo-com-media`, StorageClass `local-pie-ssd`, `ReadOnlyMany` |

## 1. What lands where

**This repository** holds the following, and none of it reaches the cluster by
merge alone:
- the Namespace and its restricted v1.36 Pod Security labels;
- the budget and LimitRange, bound to the shared site evidence;
- the connector budget raised by one connector;
- the nine RBAC objects and the impersonation name in `access.yaml`;
- the fourth connector in the `cloudflare-public` chart;
- the per-namespace policy tables, which start the chart source PENDING;
- the reviewed artifacts this ceremony applies.

**`snaraj/platform-k8s-infra`** holds the composition under
`kubernetes/websites/hospedajedonlolo-com/`. It has four manifests:
- `default-deny`;
- the `OCIRepository` at the all-zero sentinel digest, with this site's
  publisher identity;
- the `HelmRelease`, suspended, with values exactly `deploymentReady: true`;
- the kustomization.

That composition merges before step 7.

**`snaraj/hospedajedonlolo.com`** publishes the signed image and chart. Its
first Release is what step 9 selects.

Two facts about that chart decide what the edge probes later accept:
- `scripts/edge-probe.sh` and `scripts/verify-exposure.sh` require the apex to
  serve exactly `<title>hospedajedonlolo.com</title>`, with no other site's
  title.
- The cross-site distinctness item compares asset filenames of the form
  `/assets/index-<hash>.js|css`. A page with none of them makes that item an
  ERROR.

## 2. One sequencing hazard: the connector release

The `cloudflare-public` HelmRelease renders every connector the chart
declares. If the live release is reconciling, the merge of issue #422 renders
`hospedajedonlolo-com-tunnel` at once. Its Pod cannot start until its token
Secret exists. Before the owner merges, read the live release's
`spec.suspend`. If it is `false`, complete step 4 first so the Secret is
already present. As of 2026-11-01 the Secret exists, so this hazard is
already closed. If it is `true`, the Deployment appears only when the
release is next resumed. The other three Deployments render byte-identical
either way.

## 3. The ceremony

Run every command from a checkout of the merged commit. A failed `test`
operation, an unexpected `created` line or any other surprise stops the
ceremony. It is resolved by a fresh read, never by a retry.

### Step 1: Namespace and budgets

Server-dry-run first. Require that the namespace document reports
`created (server dry run)` and every other document reports `AlreadyExists`.
Then repeat without the dry-run flag.

    kubectl create --filename kubernetes/platform/prerequisites/namespaces.yaml \
      --dry-run=server --output name
    kubectl create --filename kubernetes/platform/prerequisites/resource-controls.yaml \
      --dry-run=server --output name

The second file creates exactly the `namespace-budget` ResourceQuota and
`container-defaults` LimitRange in `hospedajedonlolo-com`. The connector
budget is an UPDATE, so `create` cannot apply it. Journal the object, then
patch only the two changed limits, after tests of its resourceVersion and
their current values:

    kubectl get resourcequota namespace-budget --namespace cloudflare-public --output json
    kubectl patch resourcequota namespace-budget --namespace cloudflare-public \
      --type json --patch '[
        {"op": "test", "path": "/metadata/resourceVersion", "value": "<journalled>"},
        {"op": "test", "path": "/spec/hard/limits.cpu", "value": "2"},
        {"op": "test", "path": "/spec/hard/limits.memory", "value": "1Gi"},
        {"op": "replace", "path": "/spec/hard/limits.cpu", "value": "2500m"},
        {"op": "replace", "path": "/spec/hard/limits.memory", "value": "1280Mi"}
      ]'

The live quota carries further dimensions that are not in Git. Leave them
untouched. This patch changes nothing else.

### Step 2: Tenant authority

    kubectl create --filename kubernetes/flux-system/access.yaml \
      --dry-run=server --output name

The dry run must report exactly nine new objects:
- `ServiceAccount` `default`, `helm-reconciler`, `Role` and `RoleBinding`
  `flux-controller-impersonation`, `flux-release-reconciler` and
  `helm-reconciler`, and `RoleBinding` `hospedajedonlolo-com-reconciler`, all
  in `hospedajedonlolo-com`;
- `ServiceAccount` `hospedajedonlolo-com-reconciler` in `flux-system`.

Then run it for real. The `flux-system` impersonation Role is an UPDATE.
Journal it, and append exactly one name after a test of the complete current
list:

    kubectl patch role flux-controller-impersonation --namespace flux-system \
      --type json --patch '[
        {"op": "test", "path": "/metadata/resourceVersion", "value": "<journalled>"},
        {"op": "test", "path": "/rules/0/resourceNames", "value":
          ["naranjo-online-reconciler", "lidersea-com-reconciler", "obsync-reconciler"]},
        {"op": "add", "path": "/rules/0/resourceNames/-",
         "value": "hospedajedonlolo-com-reconciler"}
      ]'

Prove the result with `kubectl auth can-i`. `kustomize-controller` may now
impersonate the new reconciler and no other new name. The new reconciler may
`create` an OCIRepository in `hospedajedonlolo-com` and nothing in any other
namespace. `helm-reconciler` there has no `persistentvolumeclaims` verb.

### Step 3: Media volume and claim (operator-provisioned)

No PersistentVolume, claim or StorageClass enters Git, and the site's Helm
account cannot create, update or delete claims. The reviewed shape is exactly
`tests/kubernetes/fixtures/allow/storage-enumerated-local.yaml`, with these
substitutions:
- PV `hospedajedonlolo-com-media`;
- claim `hospedajedonlolo-com-media` in `hospedajedonlolo-com`, pre-bound by
  `volumeName` and, on the PV, by `claimRef`;
- `ReadOnlyMany`, `Retain`, `local-pie-ssd`;
- `operator: In` node affinity naming the node from the journal;
- `local.path` set to a directory under the enumerated local root, also from
  the journal.

Neither the node nor the path is written here. Size the claim to the published
media, which is fourteen WebP images and one video of about 20 MB. Stage the
bytes through the protected media-operator path before binding, root-owned
and not writable by the workload. The Pod mounts the claim read-only at both
levels, as the naranjo media claim does.

This step carries the same storage gates as naranjo's media claim:
- [ADR 0012](../adr/0012-heavy-media-storage.md) and safety invariant 13;
- the [storage admission](../runbooks/storage-admission.md) posture;
- the large-media terms question in the 2026-11-01 amendment to
  [ADR 0006](../adr/0006-cloudflare-zero-spend.md).

Record the owner's acceptance of each in the journal before the claim binds.

### Step 4: Tunnel, route, DNS record and token Secret

Status on 2026-11-01: the coordinator has created the Tunnel with the shape
below and the token Secret in `cloudflare-public`. The apex CNAME and the
step 8 proof remain.

All of this uses Cloudflare's own CLI and runs read-only first. Follow the
shape in the 2026-11-01 amendment to
[ADR 0015](../adr/0015-per-site-tunnels.md).
1. Create the remotely managed Tunnel `hospedajedonlolo-com`.
2. Give it exactly one public hostname rule, `hospedajedonlolo.com` to the
   origin in section 0, plus the terminal `http_status:404`.
3. Add exactly one proxied apex CNAME with automatic TTL to that Tunnel. The
   zone has no other address record.
4. Capture the Tunnel token straight into a protected mode-0600 file. It never
   reaches argv, the shell history or the terminal.
5. Create the Secret from that file, so the value never appears in a command
   line:

       kubectl create secret generic hospedajedonlolo-com-tunnel-token \
         --namespace cloudflare-public --from-file=token=<protected file>

6. Delete the protected file once the connector is proven in step 8.

### Step 5: The token revision, a reviewed change

Open a pull request in this repository. It moves only
`connectors.hospedajedonlolo-com.tokenRevision` in
`kubernetes/platform/cloudflare-public/release/release.yaml` from
`not-configured` to a fresh `rev-…` value, exactly as
[the rotation runbook](../runbooks/tunnel-token-rotation.md) moves any one
site's revision. The other three revisions stay byte-identical.

### Step 6: Source-path admission

The bootstrap-owned GitRepository in `flux-system` selects application
directories through TWO filters, and both must widen.

The first filter is sparse checkout. Apply the reviewed artifact
[hospedajedonlolo-com-source-path.patch.json](../runbooks/artifacts/hospedajedonlolo-com-source-path.patch.json).
Before applying it, substitute the journalled UID and current resourceVersion
into its two placeholder tests. It tests the branch and the exact three-path
list, then appends this one directory. `scripts/validate_repository.py` binds
the file whole.

    kubectl patch gitrepository flux-system --namespace flux-system --type json \
      --patch-file docs/runbooks/artifacts/hospedajedonlolo-com-source-path.patch.json

The second filter is the ignore allowlist (issue #385). Its exact live bytes
are not desired state in Git, so the patch is built from the journalled read.
It is applied only if that read ends in a newline, already admits the three
current directories and does not yet name this one:

    kubectl get gitrepository flux-system --namespace flux-system --output json > before.json
    jq -e '.spec.ignore | endswith("\n") and contains("!/kubernetes/websites/obsync/\n")
           and (contains("hospedajedonlolo") | not)' before.json
    jq '[{"op": "test", "path": "/metadata/resourceVersion", "value": .metadata.resourceVersion},
         {"op": "test", "path": "/spec/ignore", "value": .spec.ignore},
         {"op": "replace", "path": "/spec/ignore", "value": (.spec.ignore
           + "!/kubernetes/websites/hospedajedonlolo-com/\n"
           + "!/kubernetes/websites/hospedajedonlolo-com/**\n")}]' before.json > ignore.patch.json
    kubectl patch gitrepository flux-system --namespace flux-system --type json \
      --patch-file ignore.patch.json

Then re-read the object. Its spec must match the journal except for the one
new list entry and the two appended lines.

### Step 7: The reconciler, created suspended

    kubectl create --filename docs/runbooks/artifacts/hospedajedonlolo-com-reconciler.yaml \
      --output name

Use `create` and never `apply`, so an existing object is never adopted. The
artifact is proven under this repository's policy by a byte-identical allow
fixture. It applies one directory, under its own ServiceAccount, with
`prune: false` and `deletionPolicy: Orphan`, and it is suspended. Then prove
that the Kustomization inventory in `flux-system` grew by exactly this one
object.

### Step 8: Prove the connector

The connector starts only after step 5 merges and the `cloudflare-public`
release reconciles it.
- `hospedajedonlolo-com-tunnel` is Ready with one replica.
- Its token is mounted as a file. It is not an environment variable.
- The other three connector Deployments and Secrets are unchanged from the
  journal.
- The connector namespace has exactly one connector's worth of limit headroom.
- The Tunnel shows healthy connections and no idle connector.

### Step 9: Selection, then activation

The site publishes its first signed chart. Then one reviewed change in
`platform-k8s-infra` and one in this repository move the namespace out of the
pending set together:
- the real `(tag, digest)` pair replaces the sentinel;
- the HelmRelease is unsuspended;
- `pending_chart_namespaces` drops `hospedajedonlolo-com`.

Policy refuses either half alone.

After both merge, re-verify the digest, the signature and the acquisition
receipt, and that the media claim is `Bound`. Then patch only the
reconciler's `spec.suspend` to `false`, after tests of its UID and
resourceVersion.

### Step 10: Acceptance

- The Git source and all four tenant Kustomizations are Ready at one
  revision.
- The OCIRepository reports SourceVerified at the selected digest.
- The HelmRelease is Ready, with one ready site replica.
- `scripts/edge-probe.sh --enforce` passes over all three sites.
- `scripts/verify-exposure.sh --live` passes with the residential inputs
  supplied in the shell only.
- The owner's account audit shows three Free zones, zero spend, and DNSSEC
  `active` on this zone.
- One full visual pass of the site on desktop and phone.

## 4. Recovery

These steps undo the ceremony without deleting data:
- **Suspend.** Suspend the reconciler, then the HelmRelease. Suspension stops
  reconciliation. It does not stop a running workload.
- **Remove the reconciler.** Delete it with UID and resourceVersion
  preconditions. `prune: false` and `deletionPolicy: Orphan` keep the tenant's
  objects.
- **Restore the source filters.** Apply the inverse of each step 6 patch, with
  the same tests.
- **Close the edge.** Revoking the Tunnel token disconnects the edge at once.
  The other sites keep serving.
- **Keep the media.** The PV is `Retain`, so the media survives any of the
  above. Never delete the media directory to recover a deployment.

## 5. Capacity, re-checked

Two figures from `docs/audits/2026-09-07-obsync-capacity-evidence.md` §6 matter
here:
- requests across the namespaces were 1250m of the 1620m safe pool, which is
  77%;
- the document says to re-check that figure before any further namespace.

This site adds the shared site map's 150m, giving 1400m of 1620m, about 86%.
The connector namespace's requests ceiling is unchanged. Limits overcommit
grows by 1200m for the site and 500m for the connector. Limits are ceilings,
not reservations. The 86% figure is the one the owner accepts by merging.
