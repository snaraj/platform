# Reserved file storage: qualification before activation

This is the operator procedure for [ADR 0017](../adr/0017-reserved-file-storage.md).
It is not a live installer. The repository admits a static shape and checks a
private evidence packet; no command here allocates, formats, mounts or activates
storage. Missing or inconsistent evidence remains a NO-GO.

## Preparation order and stop conditions

1. Keep the outer application reconciler suspended and `deploymentReady: false`.
   If a retained workload already exists, stop its actual Pod/containers before
   touching their mounts; suspending reconciliation or stopping kubelet is
   insufficient. Preserve retained images, volumes, claims, application
   identity and their declared capacities. Do not reuse or format them.
2. Review the exact local SSD filesystem identity and health, available bytes
   and inodes, host/control-plane reserve, and **all** existing storage promises.
   Record retained reservations even if detached or currently sparse. Inventory
   only the explicitly owned/configured objects; unknown obligations block
   admission. Reading free space alone does not establish an allocation budget.
3. Build a private expected document naming the node, pool UUID/device,
   installed kernel, exact two profile paths, planned file lengths, inner UUIDs,
   minimum inodes, every reservation, and the chosen recovery/backup policy.
   Establish new backing identities by exclusive creation under a root-owned
   protected parent and record the creator's result. Never adopt an existing
   pathname after an ambiguous create. An interrupted operation is unresolved
   until named identity and allocation observations explain it.
4. In a separately authorized preparation, reserve the entire new file ranges
   using normal allocation, then sync each file and its parent. Reject holes,
   delayed/unknown/shared extents, multiple links and unsafe ownership. Record
   allocated blocks and complete FIEMAP logical/physical extents. Unwritten
   allocated extents are valid reservations; apparent length is insufficient.
5. Qualify the installed-kernel mechanism **before relying on it**. Formatting
   must disable discard; block both discard and zero-unmap propagation to the
   backing file, including explicit trim and the host's scheduled maintenance
   paths. Do not assume mount `nodiscard` blocks explicit trim. Do not disable
   flush/fsync or blindly apply a sysfs recipe. Test a task-owned disposable
   filesystem with nonzero eligible ranges so an empty/no-op trim cannot count
   as a negative control. Preserve full allocation after format, restart and
   explicit trim/unmap qualification. If no reviewed mechanism survives those
   tests, stop with the profile disabled.
6. Verify exact loop-to-inode mapping and separate ext4 mounts with the expected
   UUIDs and flags. Prove root-owned mode-0000 empty fallback mountpoints deny
   uid 65532 writes when absent; then prove the intended mounted roots, owned
   65532:65532 mode 0700 with no extended ACL, are writable. There must be no
   symlink, bind or nested mount and no fallback `v1` layout. Bind startup to
   mount identity; do not make SSH or the control plane depend on these mounts.
7. Re-measure non-root usable capacity, free inodes, parent availability and the
   entire reservation ledger. Claim capacity is the application's logical
   tracked-byte budget, not a physical free-space watermark. A filesystem
   reserve does not upgrade `/readyz` into physical-capacity or mount proof.
8. Prove missing/wrong mount refusal, second-consumer refusal, restart durability,
   offline restore and application quarantine/re-upload recovery using only
   disposable owned test data and the independently accepted application build.
   A known recovery defect or unperformed drill cannot be marked verified.
   Record the workload owner's backup/retention and shared-failure-domain
   decision; never infer an independent backup from history or client copies.
9. Independently review the expected document and raw observations. Run the
   bounded consistency check below and retain its exact input hashes privately.
   Create only the reviewed static class/volumes under separate authority, with
   Retain, WFFC, no expansion/default, one-node affinity and exact claim
   pre-binding. Verify API UIDs and actual bindings. Submit sanitized outcome
   evidence for a **separate** composition readiness review. Never publish the
   private packet or use the fixture corpus as runtime evidence.

## Private packet and deterministic consistency check

Use two ordinary, mode-0600 JSON files outside the repository. Each is at most
64 KiB, has no duplicate fields, and uses the closed fields below. Paths inside
the JSON are compared and never opened by the validator. The private raw
evidence manifest must identify each observation, its command/tool/kernel,
time, exact object and result; keep its hash in `rawEvidenceSha256`. In
particular, the prevention mechanism hash binds the reviewed persistent host
configuration and negative-control results, not just a prose assertion.

```sh
python3 -B scripts/validate_reserved_storage_evidence.py EXPECTED.json EVIDENCE.json
```

The only success is `evidenceConsistency: pass`, with
`activationAuthorized: false`. Rejections emit no input values or paths.
The packet's last observation must be no more than 15 minutes old and not in
the future. Recollect before activation if it becomes stale; timestamps and
hashes bind supplied evidence but cannot authenticate an operator's claims.
Review raw evidence independently even when the check passes.

| Expected document field | Required meaning |
| --- | --- |
| `schema`, `profile` | integer 1; `reserved-file-ext4-v1` |
| `node`, `poolUuid`, `poolDevice`, `kernelRelease` | Exact privately reviewed identities; ext4 UUID and major:minor device |
| `recoveryDecisionSha256` | Hash of the privately reviewed owner retention/backup, recovery and shared-failure-domain decision |
| `hostReserveBytes`, `hostReserveInodes` | Positive measured host/control-plane/recovery headroom, never a guessed zero |
| `reservations` | At most 64 named obligations including `obsync-blobs`, `obsync-journal` and every retained image; each has `identity: {device, inode}` and `reservedBytes` |
| `volumes.blobs`, `volumes.journal` | `backingFile`, `filesystemUuid`, `imageBytes`, `minimumFreeInodes`; exact profile paths, distinct non-parent UUIDs and lengths exceeding 250Gi/4Gi |

After exclusive creation resolves each backing identity, independently freeze
this expected document. `expectedSha256` binds its exact bytes; it is not an
unreviewed self-selected expectation. Preserve the earlier creation and
pre-allocation observations with the raw evidence.

| Evidence field | Required meaning |
| --- | --- |
| `schema`, `profile`, `expectedSha256`, `capturedAt`, `rawEvidenceSha256` | Version/profile above, exact expected bytes, final epoch seconds, nonzero SHA-256 of private raw evidence manifest |
| `pool` | `uuid`, `device`, `filesystem: ext4`, `node`, `capacityBytes`, `availableBeforeBytes`, `availableAfterBytes`, `availableBeforeInodes`, `availableAfterInodes`, `inventoryComplete: true` |
| `reservations` | Exactly the expected IDs, each with matching `identity`, `allocatedBeforeBytes`, `allocatedAfterBytes`; absence of a mount never removes an obligation |
| `volumes` | Exactly `blobs` and `journal`, with the records below |
| `recovery` | Exact outcomes: `missingMount`, `wrongBacking`, `secondConsumer`: `refused`; `restartDurability`, `offlineRestore`, `quarantineRecovery`: `verified`; `reconciler: suspended`, `deploymentReady: false` |

For each volume, `backing` equals the expected path. `ownership` records uid/gid
0, mode `0600`, links 1, type `regular`, ancestors
`root-owned-no-links-no-write`, ACL `none`, workloadHolePunch `denied`.
`phases` contains exactly `reserved`, `formatted`, `restarted`, `trimmed`.
Each binds `identity`, `sizeBytes`, `allocatedBytes` and up to 256 contiguous,
non-overlapping extents `{logical, physical, length, state}` covering the whole
file. States are `written` or `unwritten`; fragmented but fully covered files
are accepted. The final allocated count must match the ledger.

`mount` records `target`, `filesystem`, `uuid`, `sourceDevice`,
`sourceMajorMinor`, `backingIdentity`, `flags`, `topology`, `uid`, `gid`, `mode`,
`acl`, `usableBytes`, `freeInodes`. The loop device and major:minor pair must
agree and differ between roles; the mapping must name the expected backing
inode. Flags are the ordered profile set `[rw,nodev,nosuid,noexec,nodiscard]`,
topology is `exact-no-bind-no-nested-no-links`, and ownership is 65532:65532,
0700 with no ACL. Record effective safety options as this normalized set;
independently review additional kernel-reported flags in raw evidence rather
than silently discarding a conflicting option.

`fallback` records uid/gid 0, mode `0000`, ACL `none`, layout `absent`,
workloadWrite `denied`, and ancestors `root-owned-no-links-no-write`.
`prevention` binds `kernelRelease`, `mechanismSha256`, formatDiscard `disabled`,
loopDiscard and loopZeroUnmap `blocked`, restartEnforcement `verified`, and
explicitTrim `blocked-reservation-unchanged`. These values require actual
qualification; editing strings to match this table supplies no proof.

The capacity calculation is explicit. Before allocation require:

`sum(max(reservedBytes - allocatedBeforeBytes, 0)) + hostReserveBytes <= availableBeforeBytes`.

After preparation require:

`sum(max(reservedBytes - allocatedAfterBytes, 0)) + hostReserveBytes <= availableAfterBytes`.

Known allocations cannot exceed the pool's observed used bytes. Device/inode
pairs are unique, so aliases cannot manufacture two reservations or double
credit existing allocation. Available inodes must retain the host reserve and
cover the two new backing files. The inventory must include retained obligations;
the check cannot discover an omitted promise from a self-declared ledger.

## Failure, recovery and migration

On any mismatch, keep the application stopped, preserve files/bindings and mark
the operation unresolved. Re-identify the exact objects before retry; a partial
format or mount is not permission to recreate them. Do not fill unrelated host
storage to simulate pressure, lower retained capacity promises, or clean up a
retained image to make the ledger pass. A full or damaged shared pool takes
priority over application availability; preserve management headroom.

Supported recovery stops the writer, verifies the retained pair and application
identity, performs the supported offline check/export/restore, and proves
readiness with owned data before re-enabling clients. A new profile or
StorageClass uses new reviewed bindings and an explicit stopped migration;
preserve the old pair until acceptance. Ordinary class-name/size edits do not
migrate bound claims or expand this non-expandable class.
