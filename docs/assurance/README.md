# Platform assurance

Assurance connects a stated control to reproducible repository checks or a
current operational observation. Evidence must identify the revision and scope
it actually proves. A successful source check does not prove deployment,
network enforcement or recovery.

The [control matrix](../security/security-control-matrix.md) maps security
properties to their enforcement and evidence. The [threat model](../security/threat-model.md)
describes the assumptions and failure modes those controls address.

The [evidence ledger](evidence-ledger.jsonl) stores sanitized records validated
by `scripts/validate_assurance_ledger.py`. The
[attack-surface contract](attack-surface-manifest.json) defines the covered
security boundaries. Their versioned schemas remain authoritative in their
validators.

Keep credentials, private identifiers, raw host inventory and recovery material
outside Git and public review. Record the relevant result, exact scope and
limitations. Missing evidence, transport failure or an interrupted mutation is
an unknown outcome until inspected. Live validation follows owner-authorized
runbooks; destructive recovery drills require their own reviewed scope.
