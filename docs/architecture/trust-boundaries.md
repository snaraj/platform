# Trust boundaries

| Boundary | May initiate | Explicitly denied |
| --- | --- | --- |
| Internet visitor | HTTPS through approved Cloudflare hostname | Origin, SSH, Kubernetes API |
| `naranjo-online` Tunnel connector | DNS, its own Cloudflare Tunnel transport, `naranjo-online` TCP 8080 only | `lidersea-com` service, Pi host, admin route, Kubernetes API, arbitrary egress |
| `lidersea-com` Tunnel connector | DNS, its own Cloudflare Tunnel transport, `lidersea-com` TCP 8080 only | `naranjo-online` service, Pi host, admin route, Kubernetes API, arbitrary egress |
| `naranjo-online` pod | Serve `naranjo.online` on TCP 8080 after connector ingress | All egress, API token, other namespaces, host |
| `lidersea-com` pod | Serve `lidersea.com` on TCP 8080 after connector ingress | All egress, API token, other namespaces, host |
| `obsidian` Tunnel connector (onboarded, not deployed) | DNS, its own Cloudflare Tunnel transport, `obsidian` TCP 8080 only | Site services, Pi host, admin route, Kubernetes API, arbitrary egress |
| `obsidian` pod (onboarded, not deployed) | Serve the owner-chosen public hostname (not yet selected) on TCP 8080 after connector ingress, behind a Cloudflare Access identity or service-token policy | All egress, API token, other namespaces, host |
| naranjo media reader | Read single-link regular delivery derivatives through one rooted, read-only, mount-verified boundary | Originals, staging, metadata, links, nested mounts, writes, directory listing, other host paths |
| Media operator | Stage, checksum, derive, atomically publish, back up, and restore through the protected path | Public upload API, in-place publication, anonymous writes, runtime transcoding |
| Legacy archive operator | Preserve and verify an explicitly declared inactive archive through the protected local path | Runtime activation, public/Tunnel route, Kubernetes/Flux/CI access, broad filesystem operations, secret disclosure |
| Flux source controller | Anonymous HTTPS Git fetch | Git write, deploy keys, cluster-wide tenant mutation |
| Tenant reconciler | Named namespace resources | Other namespaces and cluster-scoped privilege |
| Admin laptop | TCP 22 after identity/device policy — SSH-only, PLAT-DEC-001; `kubectl` runs on the Pi | Kubernetes API 6443, etcd 2379/2380, kubelet 10250 (host-ingress guard), other Pi traffic, WARP-off remote access |
| Git publishing identity | Reviewed workstation commit/push through protected `main` workflow | Pi/Flux/CI storage, Cloudflare or cluster deployment authority |

Namespaces `cloudflare-public`, `naranjo-online`, `lidersea-com`, and
`obsidian` are separate policy and quota boundaries. The two rows marked
"onboarded, not deployed" describe reviewed desired state, not running objects:
that workload's chart selection is the fail-closed placeholder digest and its
release is suspended, so nothing is serving behind them yet. Kubernetes namespace is not the only control:
RBAC, NetworkPolicy, Pod Security, image policy, and separate credentials are
all required. A future PersistentVolume is cluster-scoped and therefore needs
separate admission/RBAC review; a PVC is not proof that its backing path or
mount is safe.

The protected legacy archive is not a namespace or storage class. Its exact
units, roots, mount binding, identities, and evidence remain outside Git and are
denied to Flux, Pods, every Tunnel connector, CI, and provider tooling. A future
restore requires a new isolated trust boundary and threat-model decision; a
cluster rebuild or ordinary rollback may not activate it.

The Cloudflare service boundary is also a trust and entitlement boundary. A
proxied Tunnel CNAME does not become a direct origin when a response bypasses
cache. Current self-serve terms remain incompatible with deliberate heavy-media
delivery under this repository's zero-spend constraint, so no public
large-media route may cross it.

The in-cluster storage profile is not active: this repository renders no
StorageClass, PersistentVolume, or PersistentVolumeClaim, and the fail-closed
conditional in the site chart's values schema keeps an incomplete enablement
unrepresentable. Serving stored media to the public across this boundary
remains governed by the delivery clause above.
