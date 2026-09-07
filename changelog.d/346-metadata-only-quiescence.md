### Security

- Require bounded metadata-only Job/Pod snapshots, exact owner lineage and an empty server-side selector-ServiceAccount census before source authority changes. Repeated observations reject changes detected across the barrier; immediate dispatch and UID/resourceVersion preconditions guard authority mutations.
