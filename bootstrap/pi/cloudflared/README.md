# Administrative Tunnel connector

The administrative connector runs independently of Kubernetes as a restricted
host service. It consumes a root-owned systemd credential and exposes no public
hostname, DNS record or account API credential.

The unit defines service hardening; the token validator and redaction canary
support credential custody checks. Host-token installation is retired here.
Use the [token rotation runbook](../../../docs/runbooks/tunnel-token-rotation.md)
for the operational boundary and recovery requirements.
