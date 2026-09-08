# Public Tunnel connectors

This chart defines one Cloudflare Tunnel connector per application, with a
separate Deployment, runtime token Secret and release identity for each one.
It exposes no Kubernetes Service, private route, host access or API token.

The connectors share only the namespace-wide DNS and Cloudflare transport
policies. Each origin policy binds the connector's own instance to its own
application on TCP 8080. The application chart owns the reciprocal ingress
rule. A connector cannot use these policies to reach another application.

Each origin selector names the label the ORIGIN Pods actually carry, and the
origin is not always the application. For the two sites it is: the connector
reaches the site Pod on TCP 8080. For `obsync` it is deliberately not — that
server speaks plain HTTP, so TLS terminates in-cluster in a dedicated proxy
workload and the connector reaches the PROXY on its TLS port. The only
admitted edges are connector to proxy and proxy to application; no policy here
admits connector to application. The proxy identity is a declared placeholder
until the security lane's reviewed deployment supplies the real one, so this
leg currently selects no Pod and fails closed. The values schema pins each
connector's origin label and port as `const`, which is what keeps the chart
and the policy from drifting apart.

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
