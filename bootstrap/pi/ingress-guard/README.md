# SSH-only administrative ingress

The nftables guard permits administrative SSH and denies direct access to the Kubernetes API, etcd and kubelet on the reviewed administrative interfaces. It is additive and does not own unrelated firewall rules, routes or traffic.

Use the [operation and recovery procedures](operations.md) for preconditions,
commands, verification and failure handling. Live operations require explicit
owner authorization and current evidence; source checks alone do not establish
the state of a running host or cluster.
