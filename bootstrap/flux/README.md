# Flux controller lifecycle

Flux reads public Git anonymously and reconciles through scoped service accounts.
`bootstrap.sh --generate` reproduces the three checksum-pinned controller
manifests offline. Live modes are retired.

Use the [controller installer](../../scripts/install-flux-controllers.sh) and
[installation runbook](../../docs/runbooks/flux-install.md) for a new cluster,
and the [recovery runbook](../../docs/runbooks/flux-recovery.md) for recovery.
Application reconciliation and Git source changes have separate reviewed procedures.
