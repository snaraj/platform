package main

import rego.v1

# Synthetic desired objects only. No fixture attests a real mount/reservation.
reserved_test_pv := {
  "apiVersion": "v1", "kind": "PersistentVolume",
  "metadata": {"name": "obsync-blobs-reserved"},
  "spec": {
    "capacity": {"storage": "250Gi"}, "accessModes": ["ReadWriteOnce"],
    "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "local-pie-ssd-reserved",
    "volumeMode": "Filesystem", "claimRef": {"namespace": "obsidian", "name": "obsync-blobs"},
    "local": {"path": "/mnt/local-pie-ssd-reserved/obsync-blobs"},
    "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [{
      "key": "kubernetes.io/hostname", "operator": "In", "values": ["storage-node-placeholder"],
    }]}]}},
  },
}

reserved_test_sc := {
  "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
  "metadata": {"name": "local-pie-ssd-reserved"},
  "provisioner": "kubernetes.io/no-provisioner", "volumeBindingMode": "WaitForFirstConsumer",
  "reclaimPolicy": "Retain", "allowVolumeExpansion": false,
}

reserved_test_pvc := {
  "apiVersion": "v1", "kind": "PersistentVolumeClaim",
  "metadata": {"name": "obsync-blobs", "namespace": "obsidian"},
  "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "local-pie-ssd-reserved",
    "resources": {"requests": {"storage": "250Gi"}}},
}

test_reserved_profile_positive if {
  every candidate in [reserved_test_sc, reserved_test_pv, reserved_test_pvc] {
    count(deny) == 0 with input as candidate
  }
  journal := json.patch(reserved_test_pv, [
    {"op": "replace", "path": "/metadata/name", "value": "obsync-journal-reserved"},
    {"op": "replace", "path": "/spec/capacity/storage", "value": "4Gi"},
    {"op": "replace", "path": "/spec/claimRef/name", "value": "obsync-journal"},
    {"op": "replace", "path": "/spec/local/path", "value": "/mnt/local-pie-ssd-reserved/obsync-journal"},
  ])
  count(deny) == 0 with input as journal
}

test_reserved_pv_scope_refused if {
  every patch in [
    {"op": "replace", "path": "/metadata/name", "value": "other"},
    {"op": "replace", "path": "/spec/capacity/storage", "value": "251Gi"},
    {"op": "replace", "path": "/spec/accessModes", "value": ["ReadWriteMany"]},
    {"op": "replace", "path": "/spec/persistentVolumeReclaimPolicy", "value": "Delete"},
    {"op": "replace", "path": "/spec/volumeMode", "value": "Block"},
    {"op": "replace", "path": "/spec/claimRef/name", "value": "obsync-journal"},
    {"op": "replace", "path": "/spec/claimRef/namespace", "value": "default"},
    {"op": "remove", "path": "/spec/claimRef"},
    {"op": "replace", "path": "/spec/local/path", "value": "/mnt/local-pie-ssd/obsidian/obsync-blobs"},
    {"op": "replace", "path": "/spec/local/path", "value": "/mnt/local-pie-ssd-reserved/obsync-blobs-extra"},
    {"op": "replace", "path": "/spec/local/path", "value": "/mnt/local-pie-ssd-reserved/obsync-blobs/child"},
    {"op": "replace", "path": "/spec/local/path", "value": "/mnt/local-pie-ssd-reserved/obsync-blobs/../obsync-journal"},
    {"op": "replace", "path": "/spec/local", "value": null},
    {"op": "replace", "path": "/spec/nodeAffinity", "value": {}},
    {"op": "replace", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/key", "value": "unrelated"},
    {"op": "replace", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/operator", "value": "Exists"},
    {"op": "replace", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values", "value": ["first", "second"]},
    {"op": "replace", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values", "value": [""]},
    {"op": "replace", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values", "value": [false]},
    {"op": "add", "path": "/spec/nodeAffinity/required/nodeSelectorTerms/0/unknown", "value": []},
    {"op": "add", "path": "/spec/mountOptions", "value": []},
  ] {
    candidate := json.patch(reserved_test_pv, [patch])
    some message in deny with input as candidate
    endswith(message, "must match the exact reserved-file obsync storage profile")
  }
}

test_reserved_class_refused if {
  every patch in [
    {"op": "replace", "path": "/provisioner", "value": "unknown.example/provisioner"},
    {"op": "replace", "path": "/volumeBindingMode", "value": "Immediate"},
    {"op": "remove", "path": "/volumeBindingMode"},
    {"op": "replace", "path": "/reclaimPolicy", "value": "Delete"},
    {"op": "replace", "path": "/allowVolumeExpansion", "value": true},
    {"op": "replace", "path": "/allowVolumeExpansion", "value": null},
    {"op": "add", "path": "/metadata/annotations", "value": {"storageclass.kubernetes.io/is-default-class": "true"}},
    {"op": "add", "path": "/metadata/annotations", "value": {"storageclass.beta.kubernetes.io/is-default-class": "true"}},
  ] {
    candidate := json.patch(reserved_test_sc, [patch])
    "StorageClass local-pie-ssd-reserved must match the exact reserved-file obsync storage profile" in deny with input as candidate
  }
}

test_reserved_claim_refused if {
  every patch in [
    {"op": "replace", "path": "/metadata/name", "value": "other"},
    {"op": "replace", "path": "/metadata/namespace", "value": "default"},
    {"op": "replace", "path": "/spec/resources/requests/storage", "value": "251Gi"},
    {"op": "replace", "path": "/spec/accessModes", "value": ["ReadOnlyMany"]},
    {"op": "add", "path": "/spec/volumeName", "value": "other-volume"},
    {"op": "replace", "path": "/spec/resources", "value": null},
  ] {
    candidate := json.patch(reserved_test_pvc, [patch])
    some message in deny with input as candidate
    endswith(message, "must match the exact reserved-file obsync storage profile")
  }
}

test_physical_class_cannot_select_reserved_path if {
  candidate := json.patch(reserved_test_pv, [
    {"op": "replace", "path": "/spec/storageClassName", "value": "local-pie-ssd"},
  ])
  "PersistentVolume obsync-blobs-reserved uses local path outside the enumerated local root" in deny with input as candidate
}

test_reserved_shapes_cannot_borrow_another_kind if {
  pv_as_claim := json.patch(reserved_test_pv, [{"op": "replace", "path": "/kind", "value": "PersistentVolumeClaim"}])
  claim_as_pv := json.patch(reserved_test_pvc, [{"op": "replace", "path": "/kind", "value": "PersistentVolume"}])
  pv_with_class_fields := object.union(reserved_test_pv, {
    "provisioner": "kubernetes.io/no-provisioner", "volumeBindingMode": "WaitForFirstConsumer",
    "reclaimPolicy": "Retain", "allowVolumeExpansion": false,
    "metadata": {"name": "other"},
  })
  every candidate in [pv_as_claim, claim_as_pv, pv_with_class_fields] {
    some message in deny with input as candidate
    endswith(message, "must match the exact reserved-file obsync storage profile")
  }
}
