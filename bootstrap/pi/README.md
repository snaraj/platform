# Host and cluster lifecycle

Reviewed configuration and tooling for kubeadm, containerd and host prerequisites. Recovery preserves existing administrative access and the boundaries of protected host services.

Use the [operation and recovery procedures](operations.md) for preconditions,
commands, verification and failure handling. Live operations require explicit
owner authorization and current evidence; source checks alone do not establish
the state of a running host or cluster.

The [hardening](hardening/README.md) directory carries the host baseline:
a redacted manifest, the independent assessors, the removal of unused
surfaces, the per-service egress allowlist, kernel and unit hardening, and
the verifier that proves each from live state (ADR 0018).
