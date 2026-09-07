package main

import rego.v1

# The two WEBSITES, whose charts render an identical shape. Kept separate from
# the wider workload set below because the rules guarded by it — one readiness
# scalar as the whole values block, the `deployment-ready` annotation — are
# statements about that shape, not about every reconciled workload.
site_namespaces := {"naranjo-online", "lidersea-com"}

# Every namespace reconciling a published, cosign-verified OCI chart. The two
# sites plus the obsync workload (issue #348).
chart_source_namespaces := site_namespaces | {"obsidian"}

release_kustomizations := {"platform-services", "naranjo-online", "lidersea-com", "obsync"}

# One reviewed budget per namespace, each bound to its OWN evidence document's
# exact bytes and its own exact five-value map. The sites share a map because
# they run the identical measured workload; obsync pays for one stateful
# single-writer Pod at ten times the site CPU limit, so one shared map could
# not have stated both honestly. A namespace absent here has no admissible
# budget at all.
reviewed_namespace_capacity := {
  "naranjo-online": {
    "evidence": "955a59cbf5ba0bd36f5e62349ed070a2b1eba6fb3ef072951435010edcceaf34",
    "hard": {
      "pods": "6",
      "requests.cpu": "150m",
      "requests.memory": "192Mi",
      "limits.cpu": "1200m",
      "limits.memory": "768Mi",
    },
  },
  "lidersea-com": {
    "evidence": "955a59cbf5ba0bd36f5e62349ed070a2b1eba6fb3ef072951435010edcceaf34",
    "hard": {
      "pods": "6",
      "requests.cpu": "150m",
      "requests.memory": "192Mi",
      "limits.cpu": "1200m",
      "limits.memory": "768Mi",
    },
  },
  "obsidian": {
    "evidence": "33e2aab63f9c4c8d7d01f393588fa92aa035015711a24ae167325c05353a464f",
    "hard": {
      "pods": "2",
      "requests.cpu": "200m",
      "requests.memory": "128Mi",
      "limits.cpu": "4000m",
      "limits.memory": "2Gi",
    },
  },
}

valid_reviewed_capacity_quota if {
  input.metadata.name == "namespace-budget"
  reviewed := reviewed_namespace_capacity[input.metadata.namespace]
  annotations := object.get(input.metadata, "annotations", {})
  object.get(annotations, "platform.snaraj.dev/readiness", "") == "reviewed-pi-capacity"
  object.get(annotations, "platform.snaraj.dev/capacity-evidence-sha256", "") == reviewed.evidence
  object.get(input.spec, "hard", {}) == reviewed.hard
}

deny contains msg if {
  input.kind == "HelmRelease"
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("HelmRelease %s remains suspended", [input.metadata.name])
}

# Release-mode half of the digest-selected sync contract. The scaffold renderer
# already denies an unverified chart source structurally; this rule makes the
# same denial part of what a promoted or active render must survive, so a
# release can never ship a site whose chart would be accepted unsigned.
deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in chart_source_namespaces
  object.get(object.get(input.spec, "verify", {}), "provider", "") != "cosign"
  msg := sprintf("chart source %s/%s does not require cosign verification", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "OCIRepository"
  input.metadata.namespace in chart_source_namespaces
  count(object.get(object.get(input.spec, "verify", {}), "matchOIDCIdentity", [])) != 1
  msg := sprintf("chart source %s/%s does not bind exactly one keyless publisher identity", [input.metadata.namespace, input.metadata.name])
}

deny contains msg if {
  input.kind == "Kustomization"
  input.apiVersion == "kustomize.toolkit.fluxcd.io/v1"
  input.metadata.name in release_kustomizations
  object.get(input.spec, "suspend", false) == true
  msg := sprintf("Kustomization %s remains suspended", [input.metadata.name])
}

# The verified exact-site chart is the sole workload image-identity carrier.
# Platform values are closed to one literal readiness scalar; missing, false,
# malformed, image-bearing, or otherwise extra values all take this same arm.
valid_site_release_values if {
  spec := object.get(input, "spec", null)
  is_object(spec)
  object.get(spec, "values", null) == {"deploymentReady": true}
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace in site_namespaces
  not valid_site_release_values
  msg := sprintf("HelmRelease %s values must contain exactly deploymentReady: true", [input.metadata.name])
}

# The obsync chart is a deployment-provider BINDING POINT: its values schema is
# closed and refuses a half-specified deployment, so the edge posture, the
# forwarded-address trust, the ingress peer, the Secret name, the resource
# envelope and the storage classes must all be stated. The set is therefore
# larger than the sites' single scalar and just as exact — and what it still
# does NOT contain is any image repository, tag or digest. The signed chart
# remains the sole workload image-identity carrier (ADR 0016), and an override
# added here fails this whole-object comparison rather than being merged.
#
# Three values are the transport decision of 2026-09-07 expressed as data, and
# each fails CLOSED but totally if it drifts:
#
#   * `edge.mode: none`. `cloudflare` makes the server REQUIRE the edge's
#     connecting-address and request-id headers and refuse requests that lack
#     them. Those are set by Cloudflare's HTTP edge on a PUBLIC hostname path.
#     This workload is reached over a private WARP route that never traverses
#     it, so `cloudflare` would refuse every request from the owner's own
#     device.
#   * `trustedProxyCidrs: []`. Empty is the STRICT setting: in `none` mode the
#     server believes a forwarded address only from a listed range, so an empty
#     list means it believes only the peer address — the connector Pod, the
#     sole ingress path the default-deny policy admits. A CIDR here would make
#     an `X-Forwarded-For` header believable from that range.
#   * `publicUrl: ""`. The chart's closed schema admits the empty string and
#     the application treats an unset public URL as unset — the pairing page
#     simply shows none. The owner's private name therefore never enters public
#     Git (safety invariant 12), which a sentinel hostname would have made a
#     habit of carrying.
#
# `ingress.*` names the in-cluster TLS PROXY, never the connector. Binding the
# application's ingress peer to the connector would admit the connector
# straight to the server's plain HTTP listener; naming a proxy that does not
# exist yet admits nothing, which is the fail-closed direction. The triple is a
# DECLARED PLACEHOLDER — the security lane's reviewed proxy deployment supplies
# the real identity and replaces it in that same change — and the release stays
# suspended and non-deployable until then.
#
# This repository no longer renders the obsync HelmRelease: its composition
# moved to `platform-k8s-infra`, whose manifest-shape policy pins these exact
# bytes and is the authoritative statement. This rule is the platform-side
# backstop for the same object, kept on the same terms as the two site rules
# above, which the same extraction left in place.
obsync_release_values := {
  "deploymentReady": false,
  "edge": {"mode": "none"},
  "ingress": {
    "peerAppName": "obsync-tls-proxy",
    "peerInstance": "obsync-tls-proxy-pending",
    "peerNamespace": "obsidian",
  },
  "publicUrl": "",
  "resources": {
    "limits": {"cpu": "2000m", "memory": "1Gi"},
    "requests": {"cpu": "100m", "memory": "64Mi"},
  },
  "serverKeySecret": {"key": "OBSYNC_SERVER_KEY", "name": "obsync-server-key"},
  "storage": {
    "blobs": {"capacity": "250Gi", "className": "local-pie-ssd", "size": "250Gi"},
    "journal": {"capacity": "4Gi", "className": "local-pie-ssd", "size": "4Gi"},
  },
  "trustedProxyCidrs": [],
}

deny contains msg if {
  input.kind == "HelmRelease"
  input.metadata.namespace == "obsidian"
  object.get(object.get(input, "spec", {}), "values", null) != obsync_release_values
  msg := sprintf("HelmRelease %s values are outside the reviewed obsync binding", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace in {"naranjo-online", "lidersea-com"}
  object.get(object.get(input.metadata, "annotations", {}), "platform.snaraj.dev/deployment-ready", "") != "true"
  msg := sprintf("Deployment %s is not marked ready", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ReplicaSet"
  input.metadata.namespace in {"cloudflare-public", "obsidian"} | site_namespaces
  msg := sprintf("raw tenant ReplicaSet %s/%s is forbidden in reviewed desired state", [input.metadata.namespace, input.metadata.name])
}

# Each per-workload connector Deployment must carry a resolved tunnel-token
# revision; an unresolved revision on ANY connector keeps the connector desired
# state fail-closed. Derived from the workload set so a connector added to the
# chart cannot be missing from this check.
cloudflared_connector_deployments := {instance |
  some namespace in chart_source_namespaces
  instance := sprintf("%s-tunnel", [namespace])
}

deny contains msg if {
  input.kind == "Deployment"
  input.metadata.namespace == "cloudflare-public"
  input.metadata.name in cloudflared_connector_deployments
  revision := object.get(
    object.get(object.get(object.get(input.spec, "template", {}), "metadata", {}), "annotations", {}),
    "platform.snaraj.dev/tunnel-token-revision",
    "not-configured",
  )
  revision in {"", "not-configured", "UNRESOLVED"}
  msg := "cloudflared tunnel token revision remains unresolved"
}

deny contains msg if {
  input.kind == "Deployment"
  some container in input.spec.template.spec.containers
  endswith(container.image, "@sha256:0000000000000000000000000000000000000000000000000000000000000000")
  msg := sprintf("container %s still uses the all-zero digest", [container.name])
}

deny contains msg if {
  input.kind == "ResourceQuota"
  input.metadata.namespace in chart_source_namespaces
  not valid_reviewed_capacity_quota
  msg := sprintf("workload capacity gate remains closed or lacks a hash-bound reviewed budget in namespace %s", [input.metadata.namespace])
}
