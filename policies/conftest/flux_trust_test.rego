package main

import rego.v1

# Synthetic input for the source-controller's exact storage boundary.
flux_trust_storage_fixture := {"spec": {"template": {"spec": {
  "containers": [{"name": "manager", "args": [], "resources": {
    "requests": {"ephemeral-storage": "128Mi"},
    "limits": {"ephemeral-storage": "1Gi"},
  }}],
  "volumes": [
    {"name": "data", "emptyDir": {"sizeLimit": "768Mi"}},
    {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi"}},
    {"name": "controller-ca", "projected": {"defaultMode": 292, "sources": [
      {"configMap": {"name": "flux-controller-ca-00f6a1aad627-a", "items": [
        {"key": "roots-a.pem", "path": "roots-a.pem"},
      ]}},
      {"configMap": {"name": "flux-controller-ca-00f6a1aad627-b", "items": [
        {"key": "roots-b.pem", "path": "roots-b.pem"},
      ]}},
    ]}},
  ],
}}}}

test_flux_trust_storage_exact_projection_allowed if {
  valid_source_controller_storage with input as flux_trust_storage_fixture
}

test_flux_trust_storage_widening_refused if {
  every change in [
    {"op": "remove", "path": "/spec/template/spec/volumes/2"},
    {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "extra", "emptyDir": {}}},
    {"op": "replace", "path": "/spec/template/spec/volumes/0/emptyDir/sizeLimit", "value": "1Gi"},
    {"op": "remove", "path": "/spec/template/spec/volumes/1/emptyDir/sizeLimit"},
    {"op": "remove", "path": "/spec/template/spec/containers/0/resources/limits/ephemeral-storage"},
    {"op": "replace", "path": "/spec/template/spec/volumes/2/name", "value": "other"},
    {"op": "replace", "path": "/spec/template/spec/volumes/2/projected/defaultMode", "value": 438},
    {"op": "add", "path": "/spec/template/spec/volumes/2/projected/sources/0/configMap/optional", "value": true},
    {"op": "replace", "path": "/spec/template/spec/volumes/2/projected/sources/0/configMap/name", "value": "other-roots"},
    {"op": "remove", "path": "/spec/template/spec/volumes/2/projected/sources/1"},
    {"op": "add", "path": "/spec/template/spec/volumes/2/projected/sources/-", "value": {"secret": {"name": "extra-roots"}}},
    {"op": "add", "path": "/spec/template/spec/volumes/2/hostPath", "value": {"path": "/etc/ssl/certs"}},
  ] {
    candidate := json.patch(flux_trust_storage_fixture, [change])
    not valid_source_controller_storage with input as candidate
  }
}
