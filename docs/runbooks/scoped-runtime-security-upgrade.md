# Scoped runtime security upgrade

This is the in-place maintenance procedure for the supported updates described
in [the artifact assessment](../security/supported-runtime-remediation-2026-11.md).
It does not activate a new workload, change credentials or bypass an installer
stop. Keep target bindings, before/after objects and journals outside Git.

1. Verify the protected source checks, independent review, immutable platform
   release identity/signature, exact upstream artifacts and current target.
   Preserve another working SSH/sudo recovery path. Serialize the maintenance
   with other operators and establish application health before a change.
2. For containerd, bind the active executable and config path to the inspected
   service, confirm `KillMode=process`, and authenticate all three installed
   rollback executables against the vendor archive. Check the patch-series
   source for persistent-format changes. If rollback compatibility is unknown,
   stop; never copy or delete unrelated application data to make a preflight pass.
   Stage the exact vendor archive privately, verify its digest and executable
   members, and retain root-owned, mode-0700 backup custody before replacing
   any executable. Keep the service unit, config, runc and storage unchanged.
   Restart only the named runtime service. Verify its active executable hash,
   CRI readiness and the scoped applications. Restore the recorded executables
   and restart the same service if that transaction fails, refusing to overwrite
   a concurrent operator's changes. No reboot is part of this procedure.
3. For Flux, prove the candidate in a disposable cluster using the unchanged
   controller-local role from `kubernetes/flux-system/access.yaml`, the
   per-controller roles and the existing egress rules. The controller root
   alone omits the namespaced leader-election prerequisite. Verify real Git,
   signed OCI, Kustomization and Helm reconciliation plus authorization denials.
   A CNI that does not enforce NetworkPolicy proves no network-policy property.
4. For an existing Flux installation, record the exact controller and relevant
   CRD before-state. Compare the reviewed old and new renders; authorization,
   trust mounts, security settings, selectors and egress must remain unchanged.
   Check CRD schema compatibility with the existing stored versions. Apply only
   required compatible schema additions and exact controller image changes,
   with UID/resource-version/spec preconditions. Never run the create-only
   installer over an existing installation or delete a CRD. Retain compatible
   additive schemas during image rollback; do not erase newly represented
   fields by blindly restoring an older schema. Unsupported schema changes are
   a stop. Verify actual running config digests and all scoped reconciliations.
5. For cluster connectors, identify the existing owner/reconciler before
   changing an image. A reconciled object changes through its governing GitOps
   selection; an operator-owned object uses an exact-state image-only patch.
   Preserve arguments, credentials, origin binding, replica strategy, policy
   and trust. Check the rollback image after pulling the candidate. Verify
   actual container bytes, connector readiness and representative application
   requests. The host binary installer retains its trusted-launcher stop;
   cluster delivery is not host delivery.

Each transaction is conditional on fresh evidence for that exact action. Stop
on unexpected ownership, source drift, missing recovery, or a concurrent change.
Keep residual Go/JOSE exposure separate from the repaired core conditions and
record every release, selected revision, running artifact and validation result.
