# Static storage policy and qualified local-volume profiles

## Present-state truth

This is a repository-side Conftest control, not runtime admission: no webhook
evaluates these rules in the cluster. The committed Rego and hostile fixtures
still fail closed before merge: unknown volume sources, network storage,
`hostPath`, unenumerated classes or provisioners, path traversal, missing node
affinity, data-source imports, CSI drivers, and degenerate/null shapes are
rejected.

Historical discovery receipts are not current storage inventory or evidence
that a reviewed local-volume profile is active. This repository must not claim
storage activation until current discovery, binding, restore and live-validation
evidence for the selected profile exists.

## Reviewed target posture

Future usage-export storage has one closed design:

- upstream static `local` PersistentVolume type, never `hostPath`;
- root `/mnt/local-pie-ssd`;
- StorageClass `local-pie-ssd` with
  `kubernetes.io/no-provisioner`;
- `ReadWriteOnce` access and `Retain` reclaim behavior;
- exact node affinity, a local block-device mount, no remote or nested mount,
  and no textual path traversal;
- no CSI driver, dynamic provisioner, volume-attributes class, data-source
  import, mount options, or alternate storage root.

That physical profile remains unchanged. A second, obsync-only source profile
in [ADR 0017](../adr/0017-reserved-file-storage.md) admits reserved file-backed
ext4 through `local-pie-ssd-reserved`, with exact two-claim/path binding,
non-default static provisioning, WFFC, Retain and no expansion. It does not
admit arbitrary loop storage or another workload. The
[qualification procedure](reserved-file-storage.md) requires durable
reservation, identity, ledger, absent-mount and recovery evidence; it supplies
no presumed installed-kernel trim-prevention mechanism or activation authority.

The Naranjo Helm reconciler may receive PVC lifecycle authority only. It never
gets PV, StorageClass, node, or host authority. Permanent PV/StorageClass and
host preparation stay bootstrap/operator owned; tenant reconciliation cannot
create, retarget, delete, or widen them.

## Static control

`policies/conftest/kubernetes.rego` is the only executable policy source for
this boundary. Its owner-selected enumeration is:

| Field | Exact value |
| --- | --- |
| StorageClass | `local-pie-ssd`; `local-pie-ssd-reserved` only through the complete obsync profile |
| Provisioner | `kubernetes.io/no-provisioner` |
| Physical local root | `/mnt/local-pie-ssd` |
| Reserved local paths | Exactly `/mnt/local-pie-ssd-reserved/obsync-blobs` and `/mnt/local-pie-ssd-reserved/obsync-journal`, only with their exact reserved class/PV/claim pairs |
| CSI drivers | empty |
| VolumeAttributesClass names | empty |
| PersistentVolume source types | `local`, with `csi` syntactically recognized but denied while the driver set is empty |

PersistentVolume source fields are derived by subtracting the exact known
non-source fields. A source Kubernetes adds later is therefore denied until it
is reviewed. All nested object reads are type checked so null, scalar, list,
or otherwise malformed values cannot make a Rego deny body disappear.

The workload-volume control is separate: the global source set remains
`emptyDir`, `configMap`, `secret`, `projected`, and `downwardAPI`. One positive
proof admits the signed obsync chart's exact two PVC mount pairs on its named
Deployment: blobs at `/data/blobs`, journal at `/data/journal`. It binds the
namespace, Deployment, selector/template identities, account, sole container,
complete volume list and complete mount list. A proxy, bare Pod, Job, mirror,
extra container, alternate claim, subPath or malformed source does not inherit
this exception. CSI, cloud disks, network filesystems, multi-source entries and
unknown future fields remain denied.

This static exception authorizes neither a PV nor its backing filesystem. All
runtime discovery and operator-owned storage prerequisites below still apply.

## Verification

Run:

```sh
scripts/test-policy-fixtures.sh
python3 -B -m unittest tests.security.test_storage_exposure_policy_contract
python3 -B scripts/validate_repository.py kubernetes
```

The negative corpus includes NFS, iSCSI, cloud CSI, hostPath, traversal,
multiple/absent sources, unbounded or malformed node affinity, unknown class
and provisioner, data-source imports, VolumeAttributesClass references, null
objects, and unknown Pod volume sources. Each fixture has an exact expected
Conftest attribution; a generic rejection by an unrelated rule does not count.

## Runtime closure still required

Manifest checks cannot prove what a node path really mounts. The physical
profile still requires ADR 0012 evidence: a local physical block device; reviewed
filesystem and capacity; UUID-bound mount with `nodev,nosuid,noexec`; no
symlink, bind, nested, network, loop, iSCSI, or NBD escape; backup and restore
drills; preserved SSH/control-plane headroom; exact PV/PVC binding; and live
cross-namespace denial tests. The reserved profile instead requires the full
ADR 0017 qualification and its separate readiness review; it cannot borrow a
physical-profile receipt or qualify by changing only the class name. Missing
evidence remains a NO-GO for either profile.

If live storage diverges, suspend the dependent release and preserve the
volume. Never format, delete, dynamically reprovision, or broaden reconciler
authority as a rollback shortcut.
