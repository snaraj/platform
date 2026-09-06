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

`cloudflare-account-audit.sh` provides owner-run read-only provider inspection;
`edge-probe.sh` checks the approved public edges. Tunnel credential rotation and
validation are separate from application promotion.
