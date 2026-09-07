### Changed

- Retire the legacy release-selector runtime, duplicated application manifests, and platform-side promotion train now owned by `platform-k8s-infra`.
- Advance source releases to the selector-free v3 identity while preserving exact verification of immutable v1 and v2 releases.
- Keep current repository analysis Python-only and require snapshot validation to reject an empty retained-backup set.
