# Platform tooling

These tools validate public configuration, verify release artifacts and support
owner-operated maintenance. Application repositories build and sign their own
images and Helm charts. Platform tooling verifies their exact identities before
preparing a promotion.

## Routine validation

Run `make check`, `make coverage` and `make pre-push-security` from the repository
root. CI uses the checksum-pinned installer in `ci/install-tools.sh`. The local
publication hook checks the complete outgoing history as well as the working
tree; deleting a secret from the final tree does not make publication safe.

Kubernetes checks cover rendered resources, namespace and network boundaries,
artifact identity, release state and deterministic output. Source publication
has a separate contract and does not deploy workloads.

## Operations

Use the [runbooks](../docs/runbooks/) for operation-specific prerequisites,
commands, evidence and recovery. Live actions require owner authorization.
Private inputs and observations stay outside Git, CI and PRs. Missing evidence
or an interrupted operation requires inspection before further changes.

`cloudflare-account-audit.sh` provides owner-run, redacted provider inspection
through a pinned Cloudflare `cf` CLI and exactly one explicit read-only
credential: a named profile or a short-lived API token in
`CLOUDFLARE_API_TOKEN`. A complete zero-charge verdict requires Billing Read;
API-token mode also requires API Tokens Read so the token's lifetime and
permissions can be proved. The audit covers subscriptions, current-period cost,
billing history, unpaid invoices, debt, and certificate products; denied or
ambiguous billing evidence fails closed. It schema-checks its fixed command
allowlist before authenticated reads and pages collections to exhaustion.
`edge-probe.sh` separately checks the approved public edges. Tunnel credential
rotation and validation are separate from application promotion.
