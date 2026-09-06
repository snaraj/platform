# Release-selector compatibility

This directory retains the schemas, policy and bootstrap artifacts used to verify and recover historical tag-selected sources. Current application delivery follows protected Git through the existing application reconcilers. Historical artifact verification retains its exact signed identities and version rules.

Use the [operation and recovery procedures](operations.md) for preconditions,
commands, verification and failure handling. Live operations require explicit
owner authorization and current evidence; source checks alone do not establish
the state of a running host or cluster.
