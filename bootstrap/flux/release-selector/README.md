# Release-selector compatibility

This directory retains schemas and artifacts for historical release verification.
Application delivery follows protected Git through the existing reconcilers.
Historical signatures and version rules remain part of the immutable ledger.

The legacy selector is not an application recovery path. Keep its execution and
write authority disabled during [Flux recovery](../../../docs/runbooks/flux-recovery.md).
Retained bootstrap source is historical implementation, not an instruction to
run it or restore selector authority.
