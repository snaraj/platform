# ADR 0017: Reserved file-backed ext4 for the private sync workload

- Status: Source profile; disabled pending qualification and separate readiness review
- Date: 2026-09-11
- Tracking: [issue #367](https://github.com/snaraj/platform/issues/367)

## Context and decision

An operator may need bounded writable application storage on an existing local
SSD without repartitioning it. The application already takes independent blob
and journal StorageClasses and requires POSIX directories with working flush,
locking and recovery semantics. A different physical device, logical layout or
StorageClass remains a platform binding and migration decision, not a new
application protocol.

Add one optional profile, `reserved-file-ext4-v1`, for **obsync only**. It uses
two fixed-size, fully reserved regular backing files on one local ext4 SSD
filesystem, two separate ext4 loop mounts, and static local volumes in
`local-pie-ssd-reserved`. It is not a general loop-volume permission, dynamic
provisioner, CSI driver, directory-only capacity claim or remote filesystem.
The existing `local-pie-ssd` physical profile and ADR 0012 remain unchanged.

| Role | Backing file | Exact mount / PV local path | PV / claim | Claim capacity |
| --- | --- | --- | --- | --- |
| Blobs | `/var/lib/obsync-reserved/obsync-blobs.img` | `/mnt/local-pie-ssd-reserved/obsync-blobs` | `obsync-blobs-reserved` / `obsync-blobs` | 250Gi |
| Journal | `/var/lib/obsync-reserved/obsync-journal.img` | `/mnt/local-pie-ssd-reserved/obsync-journal` | `obsync-journal-reserved` / `obsync-journal` | 4Gi |

These are profile paths, not discovered host identities or deployed objects.
Backing-file sizes must exceed claim sizes by independently measured filesystem,
reserved-block and inode overhead. Each fresh filesystem's non-root usable
capacity must meet its claim. Capacity changes require review of both this
closed admission and composition; no in-place expansion is offered.

## Reservation and failure boundary

A reserved file is a capacity reservation within a shared failure domain, not
physical isolation from the OS or control plane. SSD failure, filesystem damage,
privileged host writes and other consumers can still affect both. Host and
control-plane headroom, complete reservation accounting and workload stop
conditions are therefore prerequisites, not claims inferred from free space.
The ledger includes existing and retained reservations even while unmounted.
Existing allocated bytes are already reflected in free space; charge their
unfunded reservation balance once, plus new allocations and explicit host
headroom. Recheck the ledger after preparation and immediately before activation.

Allocation must survive the operations that ordinarily reclaim unused space.
Normal `fallocate` reserves storage; sparse `truncate`, file length and PVC
capacity do not. `mke2fs` normally discards, and a loop device can translate
discard or zero-unmap requests into backing-file hole punching. Mounting with
`nodiscard` alone does not block an explicit trim. Qualification requires
format-time discard disabled, a reviewed mechanism on the **installed kernel**
that blocks both loop discard and zero-unmap, persistence of that mechanism
through restart, and actual blocked trim/unmap qualification with allocated
extent coverage preserved after every phase. Neither an untested sysfs value
nor an empty trim result proves this property. Preserve file and directory
fsync and the underlying flush path. See the upstream
[allocation semantics](https://man7.org/linux/man-pages/man2/fallocate.2.html),
[format defaults](https://man7.org/linux/man-pages/man8/mke2fs.8.html), and
[loop implementation](https://github.com/torvalds/linux/blob/master/drivers/block/loop.c).
Upstream source explains the risk; it does not identify the installed kernel.

This ADR supplies **no presumed working discard-prevention implementation**.
If the installed kernel and host maintenance paths cannot prove the property,
this profile remains disabled. Do not weaken that gate or substitute an
ordinary writable root-filesystem directory.

## Identity, ownership and recovery

Bind the parent filesystem UUID/device, backing inode/device/length, inner
filesystem UUID, loop mapping, exact mount and node. Backing files are newly
created exclusively, root-owned, mode 0600, single-link regular files with no
extended ACL or unsafe ancestor. Workload uid 65532 cannot access or punch holes
in them. The exact mounted directories are owned 65532:65532, mode 0700,
without extended ACL, with `nodev,nosuid,noexec,nodiscard` and no link, bind or
nested mount. Underlying **unmounted** mountpoints are root-owned mode 0000,
contain no `v1` layout, and refuse a workload-uid write. A missing or wrong
mount cannot become a writable fallback.

The class is non-default, static/no-provisioner, Retain, WaitForFirstConsumer
and non-expandable. Each volume is pre-bound to its exact claim in `obsidian`
and one named node. The operator verifies the bound claim UID separately after
creation; the static fixture describes the pre-binding desired object, not
the API server's augmented status. No storage objects or host identities enter
the public desired-state tree. Tenant reconciliation gains no host, PV or
StorageClass authority.

ReadWriteOnce excludes other nodes, not other Pods. Keep the one-replica
Recreate deployment, exact consumer exclusion and cooperative journal lock.
Host mount ordering is additional protection: stopping kubelet or suspending
a reconciler does not stop already-running containers. Recovery must first
stop the application through its reviewed controller path, verify no consumer,
preserve the original volumes and identity, and then perform offline checks or
restore. Never delete a claim, reformat an existing file, or silently adopt a
different mapping as rollback.

ADR 0012's media-original backup requirements are not waived by this separate
writable workload profile. Before activation, record the workload owner's
retention/backup and shared-failure-domain decision explicitly and prove its
offline restore procedure. Client copies, application history and an etcd
snapshot are not automatically independent backups. No backup or durability
drill is claimed by accepting this source.

## Qualification and future migration

The [reserved storage procedure](../runbooks/reserved-file-storage.md) defines
the private expected identity, raw observations, ledger and recovery packet.
Its offline validator checks bounded shape and consistency only; it neither
collects observations nor sets readiness. Independent operator verification
remains required. Keep the outer reconciler suspended and
`deploymentReady: false` until a separate reviewed readiness change and live
authorization follow qualification.

A future physical disk, logical volume or storage class must separately meet
the application's POSIX/fsync/lock contract and the platform's capacity,
ownership, missing-mount and recovery requirements. Review the new profile,
stop the writer, copy/verify through the application's supported recovery
path, create new reviewed bindings, and preserve the old pair until acceptance.
Bound PVC classes are not edited in place; these static classes do not support
automatic expansion. No app code change follows merely from choosing another
qualified StorageClass.
