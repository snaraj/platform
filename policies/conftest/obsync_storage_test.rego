package main

import rego.v1

# Independent positive shape, not derived from the policy's expected fields.
# These tests exercise the source denial itself, so removing its new exception
# or turning it into a blanket PVC permission cannot pass both directions.
storage_test_input := {
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {"name": "obsync", "namespace": "obsidian"},
  "spec": {
    "selector": {"matchLabels": {
      "app.kubernetes.io/name": "obsync",
      "app.kubernetes.io/instance": "obsync",
    }},
    "template": {
      "metadata": {"labels": {
        "app.kubernetes.io/name": "obsync",
        "app.kubernetes.io/instance": "obsync",
      }},
      "spec": {
        "serviceAccountName": "obsync",
        "containers": [{"name": "obsync", "volumeMounts": [
          {"name": "blobs", "mountPath": "/data/blobs"},
          {"name": "journal", "mountPath": "/data/journal"},
        ]}],
        "volumes": [
          {"name": "blobs", "persistentVolumeClaim": {"claimName": "obsync-blobs"}},
          {"name": "journal", "persistentVolumeClaim": {"claimName": "obsync-journal"}},
        ],
      },
    },
  },
}

test_obsync_claim_pair_allowed if {
  obsync_claim_pair_allowed with input as storage_test_input
}

# Each change must retain the attribution to the PVC-source rule. Other
# hardening errors in this deliberately minimal input are not evidence for it.
test_obsync_claim_scope_refused if {
  every patch in [
    {"op": "replace", "path": "/kind", "value": "StatefulSet"},
    {"op": "replace", "path": "/metadata/name", "value": "obsync-tls-proxy"},
    {"op": "replace", "path": "/metadata/namespace", "value": "default"},
    {"op": "replace", "path": "/spec/selector/matchLabels/app.kubernetes.io~1name", "value": "other"},
    {"op": "replace", "path": "/spec/selector/matchLabels/app.kubernetes.io~1instance", "value": "other"},
    {"op": "replace", "path": "/spec/template/metadata/labels/app.kubernetes.io~1name", "value": "other"},
    {"op": "replace", "path": "/spec/template/metadata/labels/app.kubernetes.io~1instance", "value": "other"},
    {"op": "replace", "path": "/spec/template/spec/serviceAccountName", "value": "default"},
    {"op": "add", "path": "/spec/template/spec/initContainers", "value": [{}]},
    {"op": "add", "path": "/spec/template/spec/ephemeralContainers", "value": [{}]},
    {"op": "add", "path": "/spec/template/spec/containers/-", "value": {}},
    {"op": "replace", "path": "/spec/template/spec/containers/0/name", "value": "other"},
    {"op": "replace", "path": "/spec/template/spec/containers/0/volumeMounts/0/mountPath", "value": "/other"},
    {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/0/subPath", "value": "nested"},
    {"op": "replace", "path": "/spec/template/spec/volumes/0/persistentVolumeClaim/claimName", "value": "other"},
    {"op": "replace", "path": "/spec/template/spec/volumes/1/persistentVolumeClaim/claimName", "value": "obsync-blobs"},
    {"op": "add", "path": "/spec/template/spec/volumes/0/persistentVolumeClaim/unknown", "value": true},
    {"op": "replace", "path": "/spec/template/spec/volumes/0/persistentVolumeClaim", "value": null},
    {"op": "replace", "path": "/spec/template/spec/volumes/0/persistentVolumeClaim", "value": []},
    {"op": "replace", "path": "/spec/template/spec/volumes/0/persistentVolumeClaim", "value": "invalid"},
    {"op": "add", "path": "/spec/template/spec/volumes/0/hostPath", "value": {"path": "/invalid"}},
  ] {
    candidate := json.patch(storage_test_input, [patch])
    "volume blobs uses undiscovered storage source persistentVolumeClaim" in deny with input as candidate
  }
}

test_bare_pod_does_not_inherit_claim_exception if {
  candidate := {
    "kind": "Pod",
    "metadata": storage_test_input.metadata,
    "spec": storage_test_input.spec.template.spec,
  }
  "volume blobs uses undiscovered storage source persistentVolumeClaim" in deny with input as candidate
}
