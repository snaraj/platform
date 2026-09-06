# Flux controller installation

[`scripts/install-flux-controllers.sh`](../../scripts/install-flux-controllers.sh)
is the reviewed create-only installer for
[`kubernetes/flux-system/controllers`](../../kubernetes/flux-system/controllers).
It installs controller resources and their least-privilege RBAC without creating
Git sources, application reconcilers, credentials, or public routes.

Before a live operation, capture current controller, custom-resource and policy
state privately. Bind the exact reviewed commit, tools, protected kubeconfig,
context, server and Calico endpoint set. Confirm recovery access and a second
operator session. Source checks do not establish live health or authorization.

Never apply the parent `kubernetes/flux-system` root. An existing installation
requires reviewed in-place recovery; CRD deletion can destroy live source and
release objects. The retired `bootstrap/flux/bootstrap.sh` live modes cannot be
used for recovery. Anonymous source and application-sync restoration require a
separately reviewed platform procedure.

## Why the apply is ordered

The generated `allow-egress` policy is patched so that its blanket
`egress: [{}]` rule is removed. What remains selects the whole namespace for
Ingress and Egress with no allow rule: on an enforcing CNI it is a namespace
default deny. Starting controller Pods before DNS and Kubernetes API reachability
exists would deadlock leader election and cache startup.

The installer owns this order:

| Phase | Exact mutation | Invariant |
| --- | --- | --- |
| 1 | the 27 non-Deployment objects from the controller render | no controller Pod exists |
| 2 | `default-deny`, `flux-controllers-dns`, `flux-controllers-artifacts`, and `flux-controllers-kube-apiserver` | only reviewed startup flows exist |
| 2b | one `flux-api-reachability-canary` Pod | the selected-CNI in-Pod Service/API path must succeed; the Pod is then deleted and proved absent |
| 3 | the three controller Deployments | Pods start only after the executable API-path proof |
| 4 | `flux-controllers-public-https`, in a separate absent-only transaction | permitted only after scalable readiness, idleness, and exact startup-policy checks |

The canary runs as `source-controller`, carries the same `app:
source-controller` and `app.kubernetes.io/part-of: flux` labels selected by the
controller policies, uses the `source-controller` ServiceAccount, and calls
`https://kubernetes.default.svc:443/api` with the mounted ServiceAccount token
and cluster CA. It does not call the operator `--server` from inside the Pod.

## Selected-CNI API destination contract

This revision supports one reviewed dataplane contract: `--cni-provider
calico`. Before any mutation, the installer proves the live DaemonSet is exactly
`kube-system/calico-node`, has `k8s-app=calico-node`, and selects
`k8s-app=calico-node`. An API, RBAC, timeout, diagnostic, identity, or selector
failure stops the run.

Calico evaluates this workload egress after Service translation. The Pod calls
the Kubernetes Service on TCP 443, while the NetworkPolicy must name every
actual API backend as an explicit `/32` on TCP 6443. Those private backends are
provided with one or more repeated `--api-endpoint` options. Before mutation,
the sorted supplied set must equal the complete authenticated, explicitly-ready
IPv4 address set from every `kubernetes.default` EndpointSlice, with exactly the
reviewed `https`/TCP/6443 port. The bound snapshot includes each slice name,
UID, resourceVersion, address type, port, readiness, and address, and is checked
again across every mutation boundary. A missing, extra, duplicate, stale,
malformed, unready, or concurrently changed member fails closed. The endpoints
are never inferred from the operator-facing `--server`, because a local proxy,
VIP, DNS name, or future HA endpoint set can make the two surfaces different.

The committed policy keeps `192.0.2.0/32` as a non-routable sentinel. In a
mode-0700 temporary directory the installer replaces the one reviewed sentinel
block with a sorted, unique set of at most 16 canonical IPv4 `/32` peers. It
then collapses that private set back to the sentinel and requires byte identity
with the reviewed render. No other byte may change, and the private endpoint
set is neither written to Git nor printed as evidence.

A CNI other than Calico, an unproved Calico identity, IPv6, a subnet, a
duplicate, loopback, multicast, noncanonical IPv4 text, an endpoint set that is
not the complete authenticated live EndpointSlice set, or a set that does not
make the in-Pod canary succeed is a stop condition. EndpointSlice membership
proves every allowed `/32`; the canary separately proves one authenticated
Service/dataplane path. Supporting another CNI requires its own reviewed
destination and canary contract; changing the flag is not sufficient.

## Bindings shared by every live mode

`--plan`, `--apply`, and `--open-public-egress` require all of these inputs:

- `--kubeconfig`, `--context`, and `--server`: every API operation carries the
  exact tuple, and the named context must resolve to the named server;
- `--cni-provider calico` and one repeated `--api-endpoint` per private API
  backend: the policy contract is independent from the operator endpoint;
- `--expect-render-sha256`, `--expect-egress-sha256`, and
  `--expect-canary-sha256`: controller, policy-template, and executable-canary
  bytes must all reproduce review evidence;
- `--expect-commit`: binds the installer and every guard, not just its output;
- the `versions.env` Kustomize version and Linux AMD64 executable SHA-256,
  Kubernetes client version, platform kubectl binary SHA-256, and exact tagged-and-digested
  `FLUX_API_CANARY_IMAGE`.

The installer first resolves each executable, copies it into its mode-0700 work
directory, removes write permission, hashes that private copy, and only then
invokes the copy. A matching self-reported version is not provenance. The
current Kustomize executable pin deliberately admits only the reviewed official
Linux AMD64 v5.8.1 bytes for a live ceremony.

An OCI identity such as `image:vX.Y.Z@sha256:...` is both readable and
immutable; the digest remains part of the identity. Release tags remain exactly
`vX.Y.Z`.

Prepare arguments without printing the private endpoint set:

```sh
API_ENDPOINT_ARGS=(--api-endpoint "$REVIEWED_API_ENDPOINT_1")
# Append one pair per additional reviewed backend, for example:
# API_ENDPOINT_ARGS+=(--api-endpoint "$REVIEWED_API_ENDPOINT_2")

COMMON_ARGS=(
  --kubeconfig "$PROTECTED_KUBECONFIG"
  --context "$REVIEWED_CONTEXT"
  --server "$REVIEWED_SERVER"
  --cni-provider calico
  "${API_ENDPOINT_ARGS[@]}"
  --expect-render-sha256 "$REVIEWED_RENDER_SHA256"
  --expect-egress-sha256 "$REVIEWED_EGRESS_SHA256"
  --expect-canary-sha256 "$REVIEWED_CANARY_SHA256"
  --expect-commit "$REVIEWED_COMMIT"
)
```

## Step 0 — reproduce all three renders offline

```sh
./scripts/install-flux-controllers.sh --render
```

This contacts no cluster. It validates the pinned tools, immutable images,
exact 30-object controller inventory, 27 + 3 controller split, 4 + 1 policy
split, restricted Pod Security labels, deleted blanket egress, absence of Flux
custom resources and Secret objects, least-privilege effective RBAC inventory, and the
one-Pod canary shape. It prints three render SHA-256 values and the source
commit. Compare them with independently reviewed evidence; do not bless values
from the execution checkout merely because they are reproducible.

## Step 1 — plan against the exact target

```sh
./scripts/install-flux-controllers.sh --plan "${COMMON_ARGS[@]}"
```

The plan renders and validates all three surfaces, proves the selected Calico
identity, authenticates the supplied private endpoint set against the complete
live `kubernetes.default` EndpointSlice set, expands and round-trips it,
performs **client-side strict validation**, and runs read-only existence,
ownership, and server-dry-run checks. It does not create the canary or any other
object.

Where no `flux-system` Namespace exists, server dry-run cannot persist the
dry-run Namespace before validating its children
([kubernetes/kubernetes#83562](https://github.com/kubernetes/kubernetes/issues/83562)).
The expected, healthy result is exactly 19 independently creatable objects
(Namespace, eight CRDs, six ClusterRoles, four ClusterRoleBindings) and 11
namespaced children reporting `namespaces "flux-system" not found`. Any other
error, object, namespace, status, or diagnostic fails closed. Client-side strict
validation still covers all 30 objects and the policy/canary renders.

On an existing installation, `--plan` is read-only and `--apply` refuses.
A fresh-install creation ledger cannot restore an existing installation.
Investigate drift through a separately reviewed in-place recovery procedure.

## Step 2 — apply, in phases

```sh
./scripts/install-flux-controllers.sh --apply "${COMMON_ARGS[@]}"
```

Run only when the plan proves the complete fresh state and the owner has
authorized the exact target and reviewed transaction. The installer gives
every object an unpredictable 256-bit per-attempt annotation and uses
`kubectl create --save-config`, never a reconciling mutation. It creates phase
1, phase 2, creates the exact canary absent-only, waits up to 60 seconds for
`Succeeded`, reads that terminal phase independently, conditionally deletes the
Pod, and proves its exact UID gone and its name absent before creating any
controller Deployment. A concurrent same-name object can produce
`AlreadyExists` or a lost response, but cannot be adopted, rewritten, or
attributed to this attempt.

Every attempted manifest enters the transaction before its request. On failure
or `INT`, `TERM`, or `HUP`, the installer rebuilds its ledger from live objects
whose attempt annotation exactly matches. It deletes those objects newest-first
with both UID and resourceVersion in Kubernetes `DeleteOptions` preconditions,
then proves each captured UID gone. A foreign collision or concurrent
replacement is reported and left untouched; an uncertain namespaced collision
also prevents cascading Namespace deletion. A lost successful DELETE response
is accepted only after the captured UID is independently proved gone. The
installer reports `ROLLBACK INCOMPLETE` and exact residue rather than claiming
success when cleanup cannot be proved. A signal before mutation leaves the
cluster unchanged; a second signal cannot re-enter rollback.

## Step 3 — verify the controllers

Use the exact kubeconfig/context/server tuple on every command. Record only
redacted counts, names, image identities, and status fields.

```sh
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get deployment \
  source-controller kustomize-controller helm-controller
kubectl --kubeconfig "$PROTECTED_KUBECONFIG" --context "$REVIEWED_CONTEXT" \
  --server "$REVIEWED_SERVER" -n flux-system get pod,networkpolicy
```

For each Deployment, require a **positive desired replica count**,
`status.observedGeneration == metadata.generation`, and current, updated,
available, and ready replicas all equal to the positive desired count, with
**zero unavailable replicas**. This is N/N rollout evidence, not a literal
replica constant. Zero desired, generation lag, a partial rollout, missing or
malformed fields, diagnostic output, RBAC denial, timeout, or API failure is not
ready. The contract remains valid for future reviewed multi-replica/HA capacity.

Require exactly the three pinned controller images and no fourth controller.
Require the canary Pod absent. Before public egress, seven NetworkPolicies are
expected: the three hardened generated policies plus the four startup policies.

Prove idleness by listing every installed Flux CRD kind across all namespaces.
Every query must exit zero, emit no stderr, and emit zero object names. A failed
or malformed query is unknown, never empty. The installer performs this exact
fail-closed check again before phase 4.

## Step 4 — open public HTTPS, last

```sh
./scripts/install-flux-controllers.sh --open-public-egress "${COMMON_ARGS[@]}"
```

This mode refuses unless:

- all three Deployments satisfy the scalable current-generation N/N invariant;
- every Flux CRD query succeeds cleanly and returns zero objects;
- all four startup NetworkPolicies carry one canonical install-attempt identity
  and server dry-run reports each exact private endpoint-bound object
  `unchanged`;
- `flux-controllers-public-https` is absent.

The public policy is an **absent-only transaction**. It receives a fresh,
unpredictable attempt annotation and uses `create --save-config`, never a
reconciling `apply`; it never adopts, rewrites, or deletes pre-existing state.
The manifest enters the response-loss-safe transaction before creation. After a
successful response, server dry-run must report the exact attempt-bound object
`unchanged`. A lost response, signal, diagnostic, unexpected line, or poststate
drift invokes rollback, but deletion is permitted only for the matching attempt
annotation and captured UID/resourceVersion. A concurrent foreign winner is
reported and left untouched. Only exact poststate and an unchanged authoritative
EndpointSlice snapshot commit the transaction.

The rule permits public destinations on TCP 443 while excluding private,
loopback, link-local, carrier-grade-NAT, multicast, and reserved ranges. Its
intended consumers include public Git/OCI endpoints and, when separately
authorized, `fulcio.sigstore.dev`, `rekor.sigstore.dev`, and the Sigstore TUF
service. Kubernetes image pulls occur from the node network and are not granted
by this Pod NetworkPolicy.

## Step 5 — verify the closure

Require eight NetworkPolicies after phase 4, no `egress` rule on generated
`allow-egress`, the exact private API endpoint set on TCP 6443, and the public
policy exact poststate. Re-run the N/N readiness and zero-Flux-custom-resource
checks. Do not disclose private endpoints in Git, PR text, CI logs, or shared
evidence.

## Successful-install removal

A failed `--apply` already runs its own ledger-backed rollback. For a separately
authorized removal of a successful inert install,
`kubectl delete namespace flux-system` is **not sufficient**. It leaves these
18 non-namespaced objects:

```sh
kubectl delete clusterrolebinding crd-controller-flux-system \
  crd-controller-source-flux-system \
  crd-controller-kustomize-flux-system \
  crd-controller-helm-flux-system
kubectl delete clusterrole crd-controller-flux-system \
  flux-edit-flux-system flux-view-flux-system \
  crd-controller-source-flux-system \
  crd-controller-kustomize-flux-system \
  crd-controller-helm-flux-system
kubectl delete crd buckets.source.toolkit.fluxcd.io \
  externalartifacts.source.toolkit.fluxcd.io \
  gitrepositories.source.toolkit.fluxcd.io \
  helmcharts.source.toolkit.fluxcd.io \
  helmreleases.helm.toolkit.fluxcd.io \
  helmrepositories.source.toolkit.fluxcd.io \
  kustomizations.kustomize.toolkit.fluxcd.io \
  ocirepositories.source.toolkit.fluxcd.io
```

Delete the Namespace only after proving zero Flux custom resources, then remove
the exact binding, roles, and CRDs above with the same explicit target tuple.
These commands are not live authorization; they document complete inventory so a
future reviewed rollback cannot mistake Namespace deletion for full removal.

The reviewed render contains no `cluster-reconciler-flux-system` binding, so the
list above is complete **for the controller install root this repository
renders**, including the six per-controller objects. `access.yaml` contributes
only namespaced RBAC and leaves no extra cluster-scoped removal residue.
