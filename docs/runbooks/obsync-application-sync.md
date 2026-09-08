# Application sync: adding the obsync reconciler

The reviewed platform procedure that
[flux-install.md](flux-install.md) and [flux-recovery.md](flux-recovery.md)
both require before any anonymous Git source or application sync is created or
restored. Its scope is exactly one addition: a third tenant reconciler for the
`obsync` application directory in `platform-k8s-infra`, into namespace
`obsidian`. It creates no credential, no public route and no new authority
beyond the ServiceAccount and Roles this repository already declares in
`kubernetes/flux-system/access.yaml`.

**Why this is a procedure and not a manifest.** After the selector retirement
this repository declares no application reconciler object anywhere.
`flux-install.md` states that its create-only installer "installs controller
resources and their least-privilege RBAC without creating Git sources,
application reconcilers, credentials, or public routes", and that the parent
`kubernetes/flux-system` root is never applied. `flux-recovery.md` item 4
states that anonymous Git sources and application sync are restored "only
through a separately reviewed platform procedure", and that the retired
bootstrap live modes are not recovery paths. Committing a Kustomization object
under a root nothing applies would be desired state that reconciles nothing —
a manifest that reads live and is inert. The reviewed shape therefore lives
here, where the operator who applies it reads it.

## What reconciles what, in one paragraph

The bootstrap-owned, anonymous, pull-only GitRepository in `flux-system`
follows protected `main` of the application repository. Each tenant
Kustomization selects ONE application directory from it under its own
ServiceAccount, impersonated by kustomize-controller. The obsync reconciler is
the third of those and applies exactly
`./kubernetes/websites/obsync` — the default-deny NetworkPolicy, the
OCIRepository and the HelmRelease that directory contains, and nothing else.
Below that, helm-controller reconciles the HelmRelease under the namespace's
own `helm-reconciler` account. The application composition is never applied
from this repository.

## Preconditions

- An owner-authorized operation window and one named actor. This procedure is
  merged before it is run.
- The `obsidian` namespace, its budget, its LimitRange and the
  `obsync-reconciler` ServiceAccount and Roles are reconciled and current.
  They are this repository's desired state; verify them live before adding a
  reconciler that impersonates them.
- The application repository's protected `main` carries the reviewed obsync
  application directory under its own kubernetes/websites tree, together with
  its manifest-shape pins and its pending declaration. That path is quoted
  bare on purpose: it is a path in THAT repository, and this one has no such
  file to point at. Compare every manifest byte to the reviewed source.
- Recovery access and a second operator session, per flux-install.md.
- Keep the operator journal, live observations and any private binding outside
  Git.

## 1. Source-path admission

The GitRepository's own ignore and sparse-checkout boundaries currently select
exactly the two active application paths, and that restriction is what keeps
the artifact from carrying anything else. This procedure widens it by exactly
one path and nothing else:

    kubernetes/websites/naranjo-online
    kubernetes/websites/lidersea-com
    kubernetes/websites/obsync

Apply the reviewed patch,
[artifacts/obsync-source-path.patch.json](artifacts/obsync-source-path.patch.json),
after substituting the journalled UID and the current `resourceVersion` into its
two placeholder `test` operations:

    kubectl patch gitrepository flux-system --namespace flux-system \
      --type json \
      --patch-file docs/runbooks/artifacts/obsync-source-path.patch.json

Every `test` operation precedes the single `replace`, which is what makes this
safe: the patch tests the object's UID, its current `resourceVersion`, the
branch, and the COMPLETE existing path list before replacing that list, so a
source that moved under the operator fails the whole patch instead of being
overwritten. `tests/security/test_runbook_references.py` asserts that shape —
one trailing `replace`, no earlier one, and those three tests present. A failed
test stops the entire patch; never substitute a merge patch, which has no test
operation at all.

Nothing else about the source changes: the URL, `ref.branch: main`, the
interval, the timeout and the absence of any credential, alternate reference,
submodule or suspension are all unchanged.

Re-read the source afterwards and require its UID, complete spec and complete
metadata to match the journal except for that one list.

## 2. The reconciler, created suspended

Apply the reviewed artifact, byte for byte:
[artifacts/obsync-reconciler.yaml](artifacts/obsync-reconciler.yaml). It is not
reproduced here, deliberately: a runbook that pastes YAML beside the file it
ships invites the two to drift, and the first draft of this procedure did
exactly that — its inline copy carried `wait: false`, which this repository's
own Conftest policy REFUSES for every approved reconciler. The artifact is now
proven against that policy on every run:
`tests/kubernetes/fixtures/allow/obsync-reconciler-artifact.yaml` is the same
bytes, `tests/security/test_runbook_references.py` asserts they stay the same
bytes, and
`tests/kubernetes/fixtures/deny/obsync-reconciler-artifact-bypasses.yaml` is
five hostile one-field variants, each refused.

Its shape is the shape the two existing tenant reconcilers carry — same kind,
same source reference, same `prune: false`, same `deletionPolicy: Orphan`, same
one-directory path, its own ServiceAccount, `wait: true` — with one difference,
`suspend: true`.

`prune: false` and `deletionPolicy: Orphan` are not defaults being restated:
they are why removing this object later cannot delete a tenant's live
resources. `serviceAccountName` is what confines everything this reconciler
applies to the authority `access.yaml` grants in `obsidian`; without it the
apply would run as kustomize-controller itself.

Apply it CREATE-ONLY, so an existing object of the same name is never
overwritten by this procedure:

    kubectl create --filename docs/runbooks/artifacts/obsync-reconciler.yaml \
      --output name

`kubectl create` fails with `AlreadyExists` rather than adopting; never
substitute `apply`, which would silently take ownership of an object this
procedure did not create. Afterwards, prove the inventory is exactly four
Kustomizations in `flux-system` and that no fifth appeared.

## 3. What stays suspended, and what flips it live

Two independent suspensions stand between this procedure and a running
workload, and they are lifted by two different changes in this order:

1. **The HelmRelease is suspended and `deploymentReady: false`**, in the
   application repository, and its OCIRepository selects the all-zero sentinel
   digest. That composition's own validator requires exactly that state while
   the application is pending. It is lifted by ONE reviewed change in that
   repository that moves the entry from its pending map to its active map,
   records the acquisition receipt for the real v0.1.0 digest, replaces the
   sentinel, unsuspends the release and sets `deploymentReady: true` — after
   the owner ceremonies for the Tunnel token, the server-key Secret and the two
   volumes have run, and after the storage-admission decision this onboarding
   names.
2. **This Kustomization is suspended**, which is what keeps the reconciler from
   applying a directory whose release cannot install. It is lifted separately,
   by an operator `spec.suspend: false` patch that tests the object's UID and
   current `resourceVersion`, taken only after step 1 has merged and the
   digest, signature and receipt have been independently verified.

Doing them in the other order is safe but pointless: an unsuspended reconciler
applying a sentinel-digest source produces a source-controller error and no
workload. Doing step 1 without step 2 leaves the merged state unreconciled,
which is the honest state and is visible.

After both, require: current observed generation and Ready on the source and
all three Kustomizations, all applying the same revision; SourceVerified on the
chart source with the exact attempted digest; Helm readiness; and the tenant
and controller boundaries unchanged. Static gates are not live evidence.

## 3b. Host directories, and the two commands that refuse while it serves

The volumes the claims bind to are an operator ceremony, and the server's own
posture constrains how their directories are prepared. It refuses a volume
directory that is writable by its group or by others unless sticky, and requires
the configured path to be its own resolved form — no symlink, no `.`, no `..`.
Create them accordingly:

    /mnt/local-pie-ssd/obsidian/obsync-blobs
    /mnt/local-pie-ssd/obsidian/obsync-journal

each owned `65532:65532`, mode `0700`, with root-owned parents that are not
group- or world-writable (sticky is acceptable), and no symlink anywhere on
either path. The chart sets no `fsGroup`: group sharing is not the mechanism
here, directory ownership is. That ownership keeps OTHER accounts off the path;
it grants the workload's own uid nothing, so a second Pod of this workload is
excluded by `replicas: 1` and `strategy: Recreate` — asserted over the rendered
Deployment — rather than by the filesystem.

`obsyncd check` and `obsyncd export` take the same exclusive journal lock the
server does, so they REFUSE while `serve` is running, with
`reason=journal_locked`. Any step in this procedure or in recovery that runs
either one stops the server first and restarts it afterwards; treating the
refusal as a fault would be the wrong reading.

## 4. Recovery

Per flux-recovery.md, and nothing here is a shortcut around it. On a failed or
partial run, keep the reconciler suspended and the journal. An interrupted
write has unknown outcome until a fresh named read resolves it.

- To back out the reconciler: delete it with foreground deletion carrying its
  original UID and current `resourceVersion` as preconditions. `prune: false`
  and `deletionPolicy: Orphan` mean the tenant's applied objects survive that
  deletion, which is the point; remove them, if that is wanted, as a separate
  reviewed decision.
- To back out the source path: apply the inverse JSON Patch, testing the
  current `resourceVersion` and the three-path list, restoring the two-path
  list. Then re-verify both existing reconcilers still apply their exact
  revisions.
- Never print Secret YAML, never introduce a Git credential, and never use a
  retired bootstrap live mode to make recovery easier.

## 5. The ownership decision this procedure does not take

This repository's contract assigns the delivery lane the verification and
documentation surface and `kubernetes/flux-system/**`, and assigns namespace
creation, RBAC, controller installation and reconciliation definitions to the
platform. It does not say who may add a THIRD tenant reconciler, nor whether a
reconciler object should become committed desired state now that no reviewed
root applies one. Both questions are open, and this procedure deliberately does
not answer either:

- **Who runs this**, and under what authorization, is an owner decision. The
  procedure is written so that whoever does can be held to an exact shape.
- **Where a reconciler object should live** — a reviewed operator procedure as
  here, or a new committed root with a reviewed apply path — is a platform-lane
  decision. Recording it as committed desired state under a root that
  flux-install.md forbids applying would be the worse of the two, which is why
  this revision does not do it.

Record the answer in this section when it arrives.
