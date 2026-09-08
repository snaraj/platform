package main

import rego.v1

# The actual YAML render is the independent positive input on the normal
# render gate. Here, mutate each scalar leaf and add unknown structure to the
# closed pod/network shapes, then require the exact corresponding denial.
proxy_test_input := {
  "kind": "Deployment",
  "metadata": {"namespace": "obsidian", "name": "obsync-tls-proxy"},
  "spec": {
    "replicas": 1, "strategy": {"type": "Recreate"},
    "selector": {"matchLabels": obsync_proxy_labels},
    "template": {
      "metadata": {"labels": obsync_proxy_labels},
      "spec": obsync_proxy_pod("obsync-tls-proxy-config-0123456789"),
    },
  },
}

test_proxy_positive if {
  count(deny) == 0 with input as proxy_test_input
}

test_proxy_changed_pod_fields_refused if {
  every entry in [pair | walk(proxy_test_input.spec.template.spec, pair); not is_object(pair[1]); not is_array(pair[1])] {
    path := array.concat(["spec", "template", "spec"], entry[0])
    candidate := json.patch(proxy_test_input, [{"op": "replace", "path": path, "value": null}])
    "obsync TLS proxy must retain its exact pod, identity and certificate-only contract" in deny with input as candidate
  }
}

test_proxy_additional_pod_field_refused if {
  candidate := json.patch(proxy_test_input, [{"op": "add", "path": ["spec", "template", "spec", "unknown"], "value": true}])
  "obsync TLS proxy must retain its exact pod, identity and certificate-only contract" in deny with input as candidate
}

test_proxy_exception_does_not_follow_relabelling if {
  every patch in [
    {"op": "replace", "path": "/metadata/name", "value": "another"},
    {"op": "replace", "path": "/metadata/namespace", "value": "default"},
    {"op": "replace", "path": "/kind", "value": "Job"},
  ] {
    candidate := json.patch(proxy_test_input, [patch])
    "container nginx image must use an approved registry and full digest" in deny with input as candidate
  }
}

test_proxy_network_fields_refused if {
  base := {"kind": "NetworkPolicy", "metadata": {"namespace": "obsidian", "name": "obsync-tls-proxy"}, "spec": obsync_proxy_network}
  every entry in [pair | walk(obsync_proxy_network, pair); not is_object(pair[1]); not is_array(pair[1])] {
    candidate := json.patch(base, [{"op": "replace", "path": array.concat(["spec"], entry[0]), "value": null}])
    "obsync TLS proxy NetworkPolicy must retain the exact connector, backend and DNS edges" in deny with input as candidate
  }
}

test_additive_sibling_network_policy_refused if {
  candidate := {"kind": "NetworkPolicy", "metadata": {"namespace": "obsidian", "name": "extra"}, "spec": {"podSelector": {}, "ingress": [{}]}}
  "obsidian NetworkPolicy is outside the exact default-deny, application and TLS proxy set" in deny with input as candidate
}

test_proxy_service_widening_refused if {
  base := {"kind": "Service", "metadata": {"namespace": "obsidian", "name": "obsync-tls-proxy"}, "spec": obsync_proxy_service}
  every patch in [
    {"op": "replace", "path": "/spec/type", "value": "NodePort"},
    {"op": "replace", "path": "/spec/ports/0/port", "value": 80},
    {"op": "add", "path": "/spec/ports/-", "value": {"port": 80}},
    {"op": "replace", "path": "/spec/selector", "value": {}},
  ] {
    candidate := json.patch(base, [patch])
    "obsync TLS proxy Service must expose only its exact private HTTPS selector and port" in deny with input as candidate
  }
}

test_proxy_unreviewed_config_refused if {
  every payload in [null, {}, {"nginx.conf": null}, {"nginx.conf": "unreviewed"}] {
    candidate := {"kind": "ConfigMap", "metadata": {"namespace": "obsidian", "name": "obsync-tls-proxy-config-0123456789"}, "data": payload, "immutable": true}
    "obsync TLS proxy ConfigMap must contain only the immutable reviewed nginx.conf" in deny with input as candidate
  }
}
