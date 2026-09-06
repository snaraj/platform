# Flux recovery

1. Confirm recovery access, node and API health, stacked etcd, CoreDNS, audit and
   encryption evidence before changing Flux. Keep observations and private
   target bindings outside Git. A configured encryption flag alone does not
   prove encrypted storage.
2. Compare controller images, effective RBAC, policy and current readiness with
   the exact reviewed manifests. For an absent installation, use the bound
   [controller installation procedure](flux-install.md). Its create-only apply
   refuses an existing installation; recover existing controllers through a
   separately reviewed in-place procedure.
3. Verify source, kustomize and helm controller readiness, narrow service-account
   authority, disabled cross-namespace references and disabled remote bases.
4. Restore anonymous Git sources and application sync only through a separately
   reviewed platform procedure. Preserve exact source identity, verified artifact
   digests, explicit tenant ServiceAccounts and `prune: false`. Retired Flux
   bootstrap live modes and the legacy tag selector are not recovery paths.
5. Prefer a reviewed Git revert for bad desired state. Before resuming a
   suspended release, render and policy-check the exact revision and verify its
   signatures and digests. Confirm current revisions and health afterward.

Never print Secret YAML or introduce Git credentials to make recovery easier.
