# Software maintenance

Use the newest stable versions that work together. Release candidates, mutable
image tags and an unsupported component combination are not upgrade targets.
Review upstream release and security notes, artifact signatures/checksums,
architecture and recovery compatibility before changing the pinned set.

The daily **Software currency** workflow compares public `versions.env` pins
with official upstream releases. `UPDATE` means a candidate needs review;
`UNKNOWN` means verification failed. Both fail the scheduled job. A newer
Kubernetes minor is shown separately while the approved minor's latest patch
remains the candidate. The workflow is read-only and runs independently of
deterministic PR checks; it does not install software or merge changes.

Dependabot checks Actions every calendar day and proposes updates through the
normal PR controls. Security updates retain their alert-triggered path. Tool
installers, image digests and coupled version assertions must change atomically
with their pins. Application dependencies belong to their owning repositories.
The frozen selector build retains its reviewed inputs until retirement.

## Select a compatible set

- Kubernetes must stay within the network plugin's tested support range.
  Follow upstream kubeadm ordering and version skew; never skip a minor.
- Keep etcd, CoreDNS and pause on the exact supported kubeadm bundle, with
  matching recovery and CRI tools. A standalone project's newer release does
  not establish compatibility with this control plane.
- Upgrade the Flux CLI, generated CRDs and three controller images as a bundle.
  Reapply and test the authored RBAC, controller-security and network-policy
  patches; an unmodified upstream export is not the platform install surface.
- Keep connector updates separate from control-plane maintenance. A restart
  can interrupt traffic and an administrative connector can interrupt recovery
  access. Retain a working independent recovery path before replacing either.

## Execute and verify

Bind the owner-authorized transaction to current protected source, exact live
object identities, verified new and rollback artifacts, and current health.
Keep the inventory and operator evidence private. Repository and source-release
success describe desired state; they do not prove deployment.

Before a control-plane or runtime change, verify the backup and off-device
recovery prerequisites in [disaster recovery](disaster-recovery.md). A runtime,
kernel, storage or mount change also needs recovery for affected persistent
data; an etcd snapshot alone cannot provide it. Never use a broad workload
eviction or discovery operation across unrelated services.

Use one component transaction at a time. Follow the owning GitOps path for
reconciled resources and a reviewed bounded operator procedure for host or
bootstrap-owned resources. The Flux installer is create-only and cannot upgrade
an existing installation. Do not delete CRDs, run `kubeadm reset`, force through
an ownership conflict or discard unknown state.

After each transaction, prove the running version/digest, current-generation
readiness, zero rollout residue, relevant API/DNS/network-policy behavior and
application/public health. Read back the result after any interrupted write.
Stop before the next component on a mismatch; restore the affected component's
compatible prior state through its recovery procedure. Revalidate access and
health after rollback. Record dated observed versions separately from desired
pins, then close the deployment work only when they agree.
