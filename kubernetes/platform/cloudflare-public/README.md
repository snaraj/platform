# Public Tunnel connectors

This chart defines one Cloudflare Tunnel connector per application, with a
separate Deployment, runtime token Secret and release identity for each site.
It exposes no Kubernetes Service, private route, host access or API token.

The connectors share only the namespace-wide DNS and Cloudflare transport
policies. Each origin policy binds the connector's site-scoped instance to its
own application on TCP 8080. The application chart owns the reciprocal ingress
rule. A connector cannot use these policies to reach the other application.

Runtime token values stay on the cluster. They never enter this chart, Git,
CI or the release Kustomization. The structural example is excluded from
reconciliation and cannot be used as a runtime credential.

Reconciliation and rollout follow the [Tunnel rotation runbook](../../../docs/runbooks/tunnel-token-rotation.md)
and [edge operations](../../../docs/runbooks/edge-remediation-and-rotation.md).
Activation requires reviewed artifact identities, current provider and workload
checks, the owner-created runtime Secrets and verified recovery. A suspended
release remains suspended until those prerequisites are proven.

The [per-site Tunnel decision](../../../docs/adr/0015-per-site-tunnels.md)
describes identity isolation and public routing. The administrative Tunnel has
its own host-level lifecycle.
