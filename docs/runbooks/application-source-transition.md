# Application Git source ownership and recovery

`platform-k8s-infra` owns application composition. Application repositories own
signed charts and images; `platform` owns the cluster's installed hard controls.
The bootstrap-owned application GitRepository is anonymous and pull-only. Its
two existing tenant reconcilers retain their names, ServiceAccounts, source
references, paths, `prune: false` and `deletionPolicy: Orphan`.

This is the operator contract for moving the source between the original
platform repository and the extracted application repository. A reviewed source
change and a source Release do not establish mutation authority or prove live
convergence. Normal application selection changes remain reviewed GitOps.

## Prerequisites

- Obtain an explicit owner-authorized operation window and one named actor.
  Merge this procedure before handoff. Independently review the exact executable
  operator package against this contract; retain its hashes and test evidence
  privately. Temporary operation code and host-specific inputs stay outside Git.
- Verify the destination repository's immutable object ID, protected main SHA,
  signed linear history, strict required checks, owner-only PR update restriction
  and core rules with no bypass. Re-run its artifact verification and compare
  every application manifest byte to the current source. Stop on head movement
  until the new state is independently verified.
- Prove source/application health, controller configuration, tenant RBAC,
  namespace restrictions, deployment image digests and public HTTPS readiness.
  Capture only named authorized resources and selected non-secret fields.
  Never collect Secret values, environment, mounts or unrelated namespaces.
- Keep a mode-0600, single-link recovery journal in an owned mode-0700 directory
  outside Git. Bind the complete source spec/annotations and application desired
  state to object UIDs. Record resource versions; reject unknown desired fields,
  owners, finalizers or resources. Refuse symlinks, public permissions and
  overwritten recovery files.

## Source handoff

The source spec remains exactly: public anonymous HTTPS URL, `ref.branch: main`,
one-minute interval, sixty-second timeout, and the existing ignore/sparse-checkout
boundaries selecting only both application paths. No credentials, alternate
references, submodules, includes, additional paths or suspension are introduced.

After the legacy selector is inert as described below, re-read the named source.
Its UID and complete semantic state must still match the journal. Apply one JSON
Patch that tests current resourceVersion, original UID, complete spec and complete
metadata, then changes only URL to
`https://github.com/snaraj/platform-k8s-infra.git` and removes the nine legacy
selector annotations. Whole metadata binds both an existing annotation map and
its absence. A failed test stops the entire patch; never substitute merge patch.

Poll boundedly for the exact verified destination artifact revision. Require
current observed generation and Ready on the source and both existing
Kustomizations, with both parents applying that revision. Require unchanged OCI
signature/digest specifications, current SourceVerified, current Helm readiness
and the exact attempted chart digest. Recheck deployment image digests, tenant
and controller boundaries and public HTTPS. Static gates are not live evidence.

## Legacy selector retirement

Before any mutation, capture all nine exact selector objects: CronJob,
RoleBinding, Role, ServiceAccount, DNS/public/API NetworkPolicies, admission
binding and admission policy. Validate their complete normalized bodies against
the reviewed frozen model and retain every original UID/resourceVersion.

Require the CronJob suspended, no active references and no execution residue.
Use complete control-namespace Job and Pod collections negotiated as
`meta.k8s.io/v1` `PartialObjectMetadataList`, without a full-object fallback.
Require explicit list/item types, namespace and UID identities, owner lineage,
resource versions, no continuation and `remainingItemCount` absent or integer zero. Bound each collection
and reject malformed or unknown ownership. Retain only identity/lineage metadata.
An additional exact server-side Pod ServiceAccount filter must return no items;
labels cannot prove absence. Any selector Job lineage or selector-account Pod
stops retirement, regardless of phase; no Pod specifications or status are needed.

Before each authority change, repeat the complete census twice. Every collection
must carry a nonempty resource version, but collection resource versions are
snapshot markers and need not be equal. Reduce each collection to the exact item
identities already described, including each object's resource version and closed
owner references, and require those projections to match across both rounds.
Both rounds must also show the same captured CronJob UID and complete body,
suspended with an empty active-reference list, an empty selector-account census
and no selector Job or Pod lineage. These matching observations prove the
required current state at both observations; they do not prove that no transient
event occurred between them.

Dispatch the authority mutation immediately after its barrier. The census is an
observation, not a lock: UID/resourceVersion compare-and-swap preconditions guard
each authority mutation against concurrent target changes. Fix namespace,
collection limits and the exact ServiceAccount filter in the reviewed operator
package; never accept a caller-supplied API path or query.

First atomically test the RoleBinding UID, current resourceVersion, whole roleRef
and sole expected subject, then empty its subjects. A named after-read must prove
the same RoleBinding UID and current object with an empty subject list. Repeat the
complete two-round current-state barrier after this quarantine. Then prove that a
fresh SubjectAccessReview for the selector ServiceAccount with its normal groups
denies `patch` on the exact GitRepository. Missing responses, transport failures,
malformed or differently scoped requests and authorization evaluation errors are
failures. Re-read the source and immediately construct and dispatch the whole-spec,
whole-metadata, UID and current-resource-version compare-and-swap. Keep the
CronJob suspended throughout.

After source convergence, delete in this order: CronJob, inert RoleBinding, Role,
ServiceAccount, DNS/public/API NetworkPolicies, admission binding, admission
policy. Before each deletion recheck source/application health, authorization
denial, quiescence and every remaining target's original UID and normalized body.
Use the exact API path with foreground DeleteOptions containing original UID and
current resourceVersion preconditions. Never force or perform name-only deletion.

Wait for each foreground deletion to finish. Accept absence only from a matching
named Kubernetes NotFound response; blanks, forbidden responses and replacement
objects never count. A skipped later object stops the sequence. Finally prove all
nine names absent, no execution residue, continued authorization denial and all
source/application/HTTPS checks still passing. Only then remove the unused
platform-side application manifests and selector source through a reviewed PR.

## Recovery

An interrupted write has unknown outcome until a fresh named read resolves it.
On failed convergence, retain the journal and keep the selector inert. Match the
current source to the exact expected forward state; using its current resource
version, atomically test UID, complete spec and metadata before restoring only
the captured source spec/annotations. Never restore selector subjects, resume
the CronJob or recreate retired resources. Concurrent source drift stops rollback.

Verify the prior protected-main revision, unchanged application identities,
current readiness, deployment digests and public HTTPS. Retain recovery material
until the intended healthy state or safe rollback is established. Release the
operation slot only after resulting-state verification, never on command success.

[Flux source behavior](https://fluxcd.io/flux/components/source/gitrepositories/),
[Helm digest status](https://fluxcd.io/flux/components/helm/helmreleases/) and
[Kubernetes deletion](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/) and
[metadata-only API responses](https://kubernetes.io/docs/reference/using-api/api-concepts/#metadata-only-fetches) define the controller and API semantics used here.
