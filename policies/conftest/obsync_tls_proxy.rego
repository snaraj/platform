package main

import rego.v1

# The exception is one complete workload, not a second image/account allowed
# throughout the namespace. Keeping the pod contract literal makes added
# containers, volumes, env, listeners or privilege fields fail closed.
obsync_proxy_labels := {
  "app.kubernetes.io/name": "obsync-tls-proxy",
  "app.kubernetes.io/instance": "obsync-tls-proxy",
}

obsync_proxy_image := "docker.io/nginxinc/nginx-unprivileged:1.30.4-alpine@sha256:442753882674b49ae2c1de83ed67896131c0777f56df5005e356e62bc3f7e7ce"

obsync_proxy_deployment if {
  input.kind == "Deployment"
  input.metadata.namespace == "obsidian"
  input.metadata.name == "obsync-tls-proxy"
}

obsync_proxy_pod(config_name) := {
  "automountServiceAccountToken": false,
  "serviceAccountName": "obsync-tls-proxy",
  "terminationGracePeriodSeconds": 30,
  "securityContext": {
    "runAsNonRoot": true, "runAsUser": 101, "runAsGroup": 101,
    "fsGroup": 101, "seccompProfile": {"type": "RuntimeDefault"},
  },
  "containers": [{
    "name": "nginx", "image": obsync_proxy_image,
    "imagePullPolicy": "IfNotPresent",
    "command": ["nginx"],
    "args": ["-c", "/etc/obsync-proxy/nginx.conf", "-g", "daemon off;", "-e", "/dev/null"],
    "ports": [{"name": "https", "containerPort": 8443, "protocol": "TCP"}],
    "startupProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 2, "failureThreshold": 30, "timeoutSeconds": 1},
    "livenessProbe": {"tcpSocket": {"port": "https"}, "periodSeconds": 30, "timeoutSeconds": 1},
    "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/readyz", "port": "https"}, "periodSeconds": 10, "timeoutSeconds": 2},
    "resources": {
      "requests": {"cpu": "125m", "memory": "128Mi"},
      "limits": {"cpu": "500m", "memory": "256Mi"},
    },
    "securityContext": {
      "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
      "capabilities": {"drop": ["ALL"]},
    },
    "volumeMounts": [
      {"name": "config", "mountPath": "/etc/obsync-proxy", "readOnly": true},
      {"name": "leaf", "mountPath": "/etc/obsync-tls", "readOnly": true},
      {"name": "runtime", "mountPath": "/tmp"},
    ],
  }],
  "volumes": [
    {"name": "config", "configMap": {"name": config_name}},
    {"name": "leaf", "secret": {
      "secretName": "obsync-tls-leaf", "defaultMode": 288,
      "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}],
    }},
    {"name": "runtime", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
  ],
}

valid_obsync_proxy_pod if {
  obsync_proxy_deployment
  input.spec.selector == {"matchLabels": obsync_proxy_labels}
  input.spec.template.metadata == {"labels": obsync_proxy_labels}
  config_name := pod_spec.volumes[0].configMap.name
  regex.match(`^obsync-tls-proxy-config-[a-z0-9]{10}$`, config_name)
  pod_spec == obsync_proxy_pod(config_name)
}

valid_obsync_proxy_container(container) if {
  valid_obsync_proxy_pod
  container == pod_spec.containers[0]
}

valid_tenant_volume(namespace, volume) if {
  namespace == "obsidian"
  valid_obsync_proxy_pod
  volume in pod_spec.volumes
}

deny contains "obsync TLS proxy must retain its exact pod, identity and certificate-only contract" if {
  obsync_proxy_deployment
  not valid_obsync_proxy_pod
}

obsync_proxy_service := {
  "type": "ClusterIP", "selector": obsync_proxy_labels,
  "ports": [{"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"}],
}

deny contains "obsync TLS proxy Service must expose only its exact private HTTPS selector and port" if {
  input.kind == "Service"
  input.metadata.namespace == "obsidian"
  input.metadata.name == "obsync-tls-proxy"
  object.get(input, "spec", null) != obsync_proxy_service
}

valid_obsync_proxy_config if {
  input.immutable == true
  object.keys(input.data) == {"nginx.conf"}
  crypto.sha256(input.data["nginx.conf"]) == "498a0c70350405c5519f51e4cd867e37ab3bd4720a86fe1eeaa91e485d7d5dd9"
  object.get(input, "binaryData", {}) == {}
}

deny contains "obsync TLS proxy ConfigMap must contain only the immutable reviewed nginx.conf" if {
  input.kind == "ConfigMap"
  input.metadata.namespace == "obsidian"
  startswith(input.metadata.name, "obsync-tls-proxy-config")
  not valid_obsync_proxy_config
}

obsync_proxy_network := {
  "podSelector": {"matchLabels": obsync_proxy_labels},
  "policyTypes": ["Ingress", "Egress"],
  "ingress": [{
    "from": [{
      "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "cloudflare-public"}},
      "podSelector": {"matchLabels": {"app.kubernetes.io/name": "cloudflare-public", "app.kubernetes.io/instance": "obsync-tunnel"}},
    }],
    "ports": [{"port": 8443, "protocol": "TCP"}],
  }],
  "egress": [
    {"to": [{
      "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "obsidian"}},
      "podSelector": {"matchLabels": {"app.kubernetes.io/name": "obsync", "app.kubernetes.io/instance": "obsync"}},
    }], "ports": [{"port": 8080, "protocol": "TCP"}]},
    {"to": [{
      "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
      "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
    }], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]},
  ],
}

deny contains "obsync TLS proxy NetworkPolicy must retain the exact connector, backend and DNS edges" if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace == "obsidian"
  input.metadata.name == "obsync-tls-proxy"
  object.get(input, "spec", null) != obsync_proxy_network
}

# NetworkPolicies add together. Pinning only the proxy's own policy would let
# a sibling policy reopen it, so the entire namespace has a closed policy set.
# The pending peer selects no real proxy; activation changes it in composition.
valid_obsidian_network_policy if {
  input.metadata.name == "default-deny"
  input.spec == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
}

valid_obsidian_network_policy if {
  input.metadata.name == "obsync-tls-proxy"
  input.spec == obsync_proxy_network
}

valid_obsidian_network_policy if {
  input.metadata.name == "obsync"
  peer := input.spec.ingress[0].from[0].podSelector.matchLabels["app.kubernetes.io/instance"]
  peer in {"obsync-tls-proxy-pending", "obsync-tls-proxy"}
  input.spec == {
    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "obsync", "app.kubernetes.io/instance": "obsync"}},
    "policyTypes": ["Ingress", "Egress"],
    "ingress": [{
      "from": [{
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "obsidian"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "obsync-tls-proxy", "app.kubernetes.io/instance": peer}},
      }],
      "ports": [{"port": 8080, "protocol": "TCP"}],
    }],
    "egress": [],
  }
}

deny contains "obsidian NetworkPolicy is outside the exact default-deny, application and TLS proxy set" if {
  input.kind == "NetworkPolicy"
  input.metadata.namespace == "obsidian"
  not valid_obsidian_network_policy
}
