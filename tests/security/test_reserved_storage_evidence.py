"""Synthetic qualification packets; these tests never inspect mounted storage."""

from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "reserved_evidence", ROOT / "scripts/validate_reserved_storage_evidence.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
GIB = 1024**3
NOW = 1_800_000_000


def encode(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def fixture():
    expected = {
        "schema": 1, "profile": "reserved-file-ext4-v1", "node": "storage-node-placeholder",
        "poolUuid": str(uuid.UUID(int=1)), "poolDevice": "8:1", "kernelRelease": "fixture-kernel",
        "recoveryDecisionSha256": "c" * 64,
        "hostReserveBytes": 100 * GIB, "hostReserveInodes": 1000,
        "reservations": {}, "volumes": {},
    }
    packet = {
        "schema": 1, "profile": "reserved-file-ext4-v1", "expectedSha256": "",
        "capturedAt": NOW, "rawEvidenceSha256": "a" * 64,
        "pool": {"uuid": expected["poolUuid"], "device": "8:1", "filesystem": "ext4",
                 "node": "storage-node-placeholder", "capacityBytes": 1024 * GIB,
                 "availableBeforeBytes": 700 * GIB, "availableAfterBytes": 445 * GIB,
                 "availableBeforeInodes": 3000, "availableAfterInodes": 2998,
                 "inventoryComplete": True},
        "reservations": {}, "volumes": {},
        "recovery": {"missingMount": "refused", "wrongBacking": "refused",
                     "secondConsumer": "refused", "restartDurability": "verified",
                     "offlineRestore": "verified", "quarantineRecovery": "verified",
                     "reconciler": "suspended", "deploymentReady": False},
    }
    for index, (role, size) in enumerate((("blobs", 252 * GIB), ("journal", 6 * GIB))):
        name = "obsync-" + role
        ident = {"device": "8:1", "inode": 100 + index}
        expected["reservations"][name] = {"identity": ident, "reservedBytes": size}
        packet["reservations"][name] = {"identity": deepcopy(ident),
                                       "allocatedBeforeBytes": 0, "allocatedAfterBytes": size}
        config = {"backingFile": "/var/lib/obsync-reserved/" + name + ".img",
                  "filesystemUuid": str(uuid.UUID(int=index + 2)),
                  "imageBytes": size, "minimumFreeInodes": 2000}
        expected["volumes"][role] = config
        observation = {"identity": deepcopy(ident), "sizeBytes": size, "allocatedBytes": size,
                       "extents": [{"logical": 0, "physical": (1 + index * 300) * GIB,
                                    "length": size, "state": "unwritten"}]}
        packet["volumes"][role] = {
            "backing": config["backingFile"],
            "ownership": {"uid": 0, "gid": 0, "mode": "0600", "links": 1,
                          "type": "regular", "ancestors": "root-owned-no-links-no-write",
                          "acl": "none", "workloadHolePunch": "denied"},
            "phases": {phase: deepcopy(observation) for phase in
                       ("reserved", "formatted", "restarted", "trimmed")},
            "mount": {"target": "/mnt/local-pie-ssd-reserved/" + name, "filesystem": "ext4",
                      "uuid": config["filesystemUuid"], "sourceDevice": "/dev/loop" + str(index),
                      "sourceMajorMinor": "7:" + str(index), "backingIdentity": deepcopy(ident),
                      "flags": ["rw", "nodev", "nosuid", "noexec", "nodiscard"],
                      "topology": "exact-no-bind-no-nested-no-links", "uid": 65532, "gid": 65532,
                      "mode": "0700", "acl": "none", "usableBytes": size - GIB, "freeInodes": 3000},
            "fallback": {"uid": 0, "gid": 0, "mode": "0000", "acl": "none", "layout": "absent",
                         "workloadWrite": "denied", "ancestors": "root-owned-no-links-no-write"},
            "prevention": {"kernelRelease": "fixture-kernel", "mechanismSha256": "b" * 64,
                           "formatDiscard": "disabled", "loopDiscard": "blocked",
                           "loopZeroUnmap": "blocked", "restartEnforcement": "verified",
                           "explicitTrim": "blocked-reservation-unchanged"},
        }
    # An unmounted retained image still has a full contractual reservation.
    ident = {"device": "8:1", "inode": 102}
    expected["reservations"]["retained-test"] = {"identity": ident, "reservedBytes": 64 * GIB}
    packet["reservations"]["retained-test"] = {"identity": deepcopy(ident),
                                               "allocatedBeforeBytes": 32 * GIB,
                                               "allocatedAfterBytes": 32 * GIB}
    return expected, packet


def put(value, path, replacement):
    keys = path.split(".")
    for key in keys[:-1]:
        value = value[int(key)] if type(value) is list else value[key]
    key = int(keys[-1]) if type(value) is list else keys[-1]
    value[key] = replacement


def fragment(observation, count, base):
    """Synthetic complete maps in logical order but reverse physical order."""
    size = observation["sizeBytes"]
    chunk, remainder = divmod(size, count)
    cursor, extents = 0, []
    for index in range(count):
        length = chunk + (index < remainder)
        extents.append({"logical": cursor, "physical": base + size - cursor - length,
                        "length": length, "state": "written" if index % 2 else "unwritten"})
        cursor += length
    observation["extents"] = extents


class ReservedEvidenceTests(unittest.TestCase):
    def check(self, expected, packet):
        payload = encode(expected)
        packet["expectedSha256"] = hashlib.sha256(payload).hexdigest()
        return gate.validate(payload, expected, packet, NOW)

    def test_complete_packet_is_consistent_but_never_authorizes_activation(self):
        expected, packet = fixture()
        self.assertEqual(self.check(expected, packet), {
            "profile": "reserved-file-ext4-v1", "evidenceConsistency": "pass",
            "activationAuthorized": False})

    def test_each_observation_refusal_has_an_independent_negative(self):
        cases = [
            ("schema", True, "schema"), ("schema", 2, "schema"), ("profile", "physical", "profile"),
            ("capturedAt", NOW + 1, "freshness"), ("capturedAt", NOW - 901, "freshness"),
            ("capturedAt", False, "number"), ("rawEvidenceSha256", "0" * 64, "digest"),
            ("pool.uuid", "wrong", "pool_identity"), ("pool.device", "8:2", "pool_identity"),
            ("pool.node", "other", "pool_identity"), ("pool.filesystem", "nfs", "pool_identity"),
            ("pool.inventoryComplete", False, "ledger_complete"),
            ("pool.inventoryComplete", 1, "ledger_complete"),
            ("pool.availableBeforeBytes", 1025 * GIB, "pool_capacity"),
            ("pool.availableAfterBytes", 1025 * GIB, "pool_capacity"),
            ("pool.availableBeforeBytes", 300 * GIB, "capacity_before"),
            ("pool.availableAfterBytes", 131 * GIB, "capacity_after"),
            ("pool.availableBeforeInodes", 1001, "pool_inodes"),
            ("pool.availableAfterInodes", 999, "pool_inodes"),
            ("reservations.retained-test.identity.inode", 999, "reservation_binding"),
            ("reservations.retained-test.allocatedBeforeBytes", 1025 * GIB, "reservation_allocation"),
            ("reservations.retained-test.allocatedAfterBytes", 1025 * GIB, "reservation_allocation"),
            ("reservations.retained-test.allocatedBeforeBytes", 400 * GIB, "ledger_used_bytes"),
            ("reservations.retained-test.allocatedAfterBytes", 400 * GIB, "ledger_used_bytes"),
            ("volumes.blobs.backing", "/var/lib/obsync-reserved/other.img", "backing_binding"),
            ("volumes.blobs.ownership.mode", "0644", "backing_ownership"),
            ("volumes.blobs.ownership.uid", False, "backing_ownership"),
            ("volumes.blobs.ownership.links", 2, "backing_ownership"),
            ("volumes.blobs.ownership.type", "symlink", "backing_ownership"),
            ("volumes.blobs.ownership.workloadHolePunch", "allowed", "backing_ownership"),
            ("volumes.blobs.mount.target", "/mnt/local-pie-ssd-reserved/obsync-blobs-extra", "mount_identity"),
            ("volumes.blobs.mount.filesystem", "overlay", "mount_identity"),
            ("volumes.blobs.mount.uuid", "wrong", "mount_identity"),
            ("volumes.blobs.mount.sourceDevice", "/dev/synthetic", "loop_source"),
            ("volumes.blobs.mount.sourceDevice", "/dev/loop00", "loop_source"),
            ("volumes.blobs.mount.sourceDevice", 7, "loop_source"),
            ("volumes.blobs.mount.sourceMajorMinor", "7:9", "loop_device"),
            ("volumes.blobs.mount.sourceMajorMinor", 7, "loop_device"),
            ("volumes.blobs.mount.backingIdentity.inode", 999, "loop_backing"),
            ("volumes.blobs.mount.flags", ["rw", "nodev", "nosuid", "noexec"], "mount_flags"),
            ("volumes.blobs.mount.topology", "bind", "mount_flags"),
            ("volumes.blobs.mount.uid", 0, "mount_ownership"),
            ("volumes.blobs.mount.uid", 65532.0, "mount_ownership"),
            ("volumes.blobs.mount.gid", True, "mount_ownership"),
            ("volumes.blobs.mount.gid", 65532.0, "mount_ownership"),
            ("volumes.blobs.mount.mode", "0770", "mount_ownership"),
            ("volumes.blobs.mount.acl", "extended", "mount_ownership"),
            ("volumes.blobs.mount.usableBytes", 249 * GIB, "usable_capacity"),
            ("volumes.blobs.mount.usableBytes", 253 * GIB, "usable_capacity"),
            ("volumes.blobs.mount.freeInodes", 1999, "usable_capacity"),
            ("volumes.blobs.fallback.mode", "0755", "fallback"),
            ("volumes.blobs.fallback.uid", False, "fallback"),
            ("volumes.blobs.fallback.layout", "present", "fallback"),
            ("volumes.blobs.fallback.workloadWrite", "allowed", "fallback"),
            ("volumes.blobs.prevention.kernelRelease", "other", "kernel_binding"),
            ("volumes.blobs.prevention.mechanismSha256", "unknown", "digest"),
            ("volumes.blobs.prevention.formatDiscard", "default", "trim_prevention"),
            ("volumes.blobs.prevention.loopDiscard", "unknown", "trim_prevention"),
            ("volumes.blobs.prevention.loopZeroUnmap", "unknown", "trim_prevention"),
            ("volumes.blobs.prevention.restartEnforcement", "unknown", "trim_prevention"),
            ("volumes.blobs.prevention.explicitTrim", "not-run", "trim_prevention"),
            ("recovery.deploymentReady", True, "recovery"),
            ("recovery.deploymentReady", 0, "recovery"),
            ("recovery.reconciler", "active", "recovery"),
            ("recovery.offlineRestore", "not-run", "recovery"),
        ]
        for path, value, reason in cases:
            with self.subTest(path=path, value=value):
                expected, packet = fixture()
                put(packet, path, value)
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    self.check(expected, packet)

    def test_expected_identity_and_reservation_refusals(self):
        cases = [
            ("schema", True, "schema"), ("schema", 2, "schema"), ("profile", "unknown", "profile"),
            ("node", "has space", "text"), ("poolUuid", "not-a-uuid", "filesystem_uuid"),
            ("recoveryDecisionSha256", "unknown", "digest"),
            ("hostReserveBytes", 0, "number"), ("hostReserveInodes", -1, "number"),
            ("reservations.retained-test.identity.device", "8:2", "reservation_identity"),
            ("reservations.retained-test.identity.device", "invalid", "device"),
            ("reservations.retained-test.identity.device", "8:01", "device"),
            ("reservations.retained-test.identity.inode", 100, "reservation_identity"),
            ("reservations.retained-test.identity.inode", False, "number"),
            ("volumes.blobs.backingFile", "/var/lib/obsync-reserved/../other", "backing_path"),
            ("volumes.blobs.filesystemUuid", str(uuid.UUID(int=1)), "filesystem_identity"),
            ("volumes.blobs.filesystemUuid", str(uuid.UUID(int=0)), "filesystem_uuid"),
            ("volumes.blobs.imageBytes", 250 * GIB, "filesystem_overhead"),
            ("volumes.blobs.imageBytes", 253 * GIB, "reserved_size"),
            ("volumes.blobs.minimumFreeInodes", True, "number"),
        ]
        for path, value, reason in cases:
            with self.subTest(path=path, value=value):
                expected, packet = fixture()
                put(expected, path, value)
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    self.check(expected, packet)

    def test_all_four_phases_require_the_same_fully_reserved_backing(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            for path, value, reason in (
                ("identity.inode", 999, "backing_identity"),
                ("sizeBytes", 251 * GIB, "backing_size"),
                ("allocatedBytes", 251 * GIB, "physical_allocation"),
                ("extents", [], "extent_count"),
                ("extents.0.logical", 512, "extent_coverage"),
                ("extents.0.length", 251 * GIB, "extent_coverage"),
                ("extents.0.length", 253 * GIB, "extent_coverage"),
                ("extents.0.state", "delalloc", "extent_state"),
                ("extents.0.state", "shared", "extent_state"),
            ):
                with self.subTest(phase=phase, path=path):
                    expected, packet = fixture()
                    put(packet, "volumes.blobs.phases." + phase + "." + path, value)
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        self.check(expected, packet)

    def test_extent_alias_is_refused_even_with_enough_reported_blocks(self):
        expected, packet = fixture()
        packet["volumes"]["blobs"]["phases"]["trimmed"]["extents"] = [
            {"logical": 0, "physical": GIB, "length": 126 * GIB, "state": "written"},
            {"logical": 126 * GIB, "physical": GIB, "length": 126 * GIB, "state": "unwritten"},
        ]
        with self.assertRaisesRegex(ValueError, "^extent_alias$"):
            self.check(expected, packet)

    def test_fragmented_complete_reservation_is_allowed(self):
        expected, packet = fixture()
        packet["volumes"]["blobs"]["phases"]["formatted"]["extents"] = [
            {"logical": 0, "physical": GIB, "length": 126 * GIB, "state": "written"},
            {"logical": 126 * GIB, "physical": 128 * GIB, "length": 126 * GIB, "state": "unwritten"},
        ]
        self.check(expected, packet)

    def test_cross_volume_extents_cannot_overlap_in_any_phase(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            for start in (14 * GIB + 1, 20 * GIB, 21 * GIB, 272 * GIB - 1):
                with self.subTest(phase=phase, start=start):
                    expected, packet = fixture()
                    packet["volumes"]["blobs"]["phases"][phase]["extents"][0]["physical"] = 20 * GIB
                    packet["volumes"]["journal"]["phases"][phase]["extents"][0]["physical"] = start
                    with self.assertRaisesRegex(ValueError, "^volume_extent_alias$"):
                        self.check(expected, packet)
            expected, packet = fixture()
            packet["volumes"]["blobs"]["phases"][phase]["extents"] = [
                {"logical": 0, "physical": 20 * GIB, "length": GIB, "state": "written"},
                {"logical": GIB, "physical": 40 * GIB, "length": 251 * GIB, "state": "unwritten"},
            ]
            packet["volumes"]["journal"]["phases"][phase]["extents"][0]["physical"] = 19 * GIB
            with self.assertRaisesRegex(ValueError, "^volume_extent_alias$"):
                self.check(expected, packet)

    def test_adjacent_volume_extents_and_cross_phase_reuse_are_allowed(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            for start in (14 * GIB, 272 * GIB):
                with self.subTest(phase=phase, adjacent=start):
                    expected, packet = fixture()
                    packet["volumes"]["blobs"]["phases"][phase]["extents"][0]["physical"] = 20 * GIB
                    packet["volumes"]["journal"]["phases"][phase]["extents"][0]["physical"] = start
                    self.check(expected, packet)
        expected, packet = fixture()
        # An extent can move between observations; only simultaneous overlap
        # in the same phase contradicts independent backing reservations.
        packet["volumes"]["blobs"]["phases"]["formatted"]["extents"][0]["physical"] = 301 * GIB
        packet["volumes"]["journal"]["phases"]["formatted"]["extents"][0]["physical"] = GIB
        self.check(expected, packet)

    def test_cross_volume_overlap_only_in_a_later_blob_extent_is_refused(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            with self.subTest(phase=phase):
                expected, packet = fixture()
                packet["volumes"]["blobs"]["phases"][phase]["extents"] = [
                    {"logical": 0, "physical": 10 * GIB, "length": 126 * GIB, "state": "written"},
                    {"logical": 126 * GIB, "physical": 300 * GIB, "length": 126 * GIB, "state": "unwritten"},
                ]
                packet["volumes"]["journal"]["phases"][phase]["extents"][0]["physical"] = 301 * GIB
                with self.assertRaisesRegex(ValueError, "^volume_extent_alias$"):
                    self.check(expected, packet)

    def test_cross_volume_overlap_only_in_a_later_journal_extent_is_refused(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            with self.subTest(phase=phase):
                expected, packet = fixture()
                packet["volumes"]["blobs"]["phases"][phase]["extents"][0]["physical"] = 100 * GIB
                packet["volumes"]["journal"]["phases"][phase]["extents"] = [
                    {"logical": 0, "physical": 10 * GIB, "length": 3 * GIB, "state": "written"},
                    {"logical": 3 * GIB, "physical": 200 * GIB, "length": 3 * GIB, "state": "unwritten"},
                ]
                with self.assertRaisesRegex(ValueError, "^volume_extent_alias$"):
                    self.check(expected, packet)

    def test_disjoint_fragmented_reservations_in_both_volumes_are_allowed(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            with self.subTest(phase=phase):
                expected, packet = fixture()
                packet["volumes"]["blobs"]["phases"][phase]["extents"] = [
                    {"logical": 0, "physical": 10 * GIB, "length": 126 * GIB, "state": "written"},
                    {"logical": 126 * GIB, "physical": 300 * GIB, "length": 126 * GIB, "state": "unwritten"},
                ]
                packet["volumes"]["journal"]["phases"][phase]["extents"] = [
                    {"logical": 0, "physical": 200 * GIB, "length": 3 * GIB, "state": "written"},
                    {"logical": 3 * GIB, "physical": 500 * GIB, "length": 3 * GIB, "state": "unwritten"},
                ]
                self.check(expected, packet)

    def test_extent_and_ledger_upper_bounds_refuse_otherwise_valid_inputs(self):
        expected, packet = fixture()
        fragment(packet["volumes"]["blobs"]["phases"]["reserved"], 8193, GIB)
        with self.assertRaisesRegex(ValueError, "^extent_count$"):
            self.check(expected, packet)
        expected, packet = fixture()
        for index in range(62):
            name, ident = "retained-" + str(index), {"device": "8:1", "inode": 200 + index}
            expected["reservations"][name] = {"identity": ident, "reservedBytes": 1}
            packet["reservations"][name] = {"identity": deepcopy(ident),
                                           "allocatedBeforeBytes": 0, "allocatedAfterBytes": 0}
        with self.assertRaisesRegex(ValueError, "^reservation_count$"):
            self.check(expected, packet)

    def test_complete_large_maps_and_maximum_packet_remain_consistent(self):
        for counts in ((800, 7), (8192, 8192)):
            with self.subTest(counts=counts):
                expected, packet = fixture()
                for index, (role, count) in enumerate(zip(("blobs", "journal"), counts)):
                    for observation in packet["volumes"][role]["phases"].values():
                        fragment(observation, count, (1 + 300 * index) * GIB)
                self.assertFalse(self.check(expected, packet)["activationAuthorized"])
                self.assertGreater(len(encode(packet)), 64 * 1024)
                self.assertLess(len(encode(packet)), 16 * 1024**2)

    def test_last_record_in_large_map_cannot_hide_a_hole_state_or_alias(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            for role, base in (("blobs", GIB), ("journal", 301 * GIB)):
                for field, reason in (("logical", "extent_coverage"),
                                      ("state", "extent_state"), ("physical", "extent_alias")):
                    with self.subTest(phase=phase, role=role, field=field):
                        expected, packet = fixture()
                        observation = packet["volumes"][role]["phases"][phase]
                        fragment(observation, 8192, base)
                        extents = observation["extents"]
                        replacement = {"logical": extents[-1]["logical"] + 1,
                                       "state": "shared", "physical": extents[0]["physical"]}
                        extents[-1][field] = replacement[field]
                        with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                            self.check(expected, packet)

    def test_last_record_cross_role_overlap_in_each_large_phase_is_refused(self):
        for phase in ("reserved", "formatted", "restarted", "trimmed"):
            for role, other in (("blobs", "journal"), ("journal", "blobs")):
                with self.subTest(phase=phase, role=role):
                    expected, packet = fixture()
                    for index, name in enumerate(("blobs", "journal")):
                        fragment(packet["volumes"][name]["phases"][phase], 8192,
                                 (1 + index * 300) * GIB)
                    current = packet["volumes"][role]["phases"][phase]["extents"]
                    target = packet["volumes"][other]["phases"][phase]["extents"]
                    current[-1]["physical"] = target[-1]["physical"]
                    with self.assertRaisesRegex(ValueError, "^volume_extent_alias$"):
                        self.check(expected, packet)

    def test_physical_interval_comparisons_do_not_grow_quadratically(self):
        comparisons = 0
        count = 2 * 8192
        def measured():
            nonlocal comparisons
            comparisons += 1
            # Bound a quadratic mutant during execution, without a timeout.
            self.assertLess(comparisons, count * 32)
        class Measured(int):
            def __lt__(self, other):
                measured()
                return int(self) < int(other)
            def __le__(self, other):
                measured()
                return int(self) <= int(other)
        # Two full maps in a phase. Odd permutation avoids an already sorted
        # fixture; count comparisons instead of relying on a timing threshold.
        physical = [(Measured((index * 7919 % count) * 2),
                     Measured((index * 7919 % count) * 2 + 2)) for index in range(count)]
        gate.disjoint(physical, "overlap")
        self.assertGreater(comparisons, 0)
        self.assertLess(comparisons, count * 32)

    def test_both_volume_reservations_are_mandatory(self):
        expected, packet = fixture()
        del expected["reservations"]["obsync-blobs"]
        del packet["reservations"]["obsync-blobs"]
        with self.assertRaisesRegex(ValueError, "^volume_reservation$"):
            self.check(expected, packet)

    def test_retained_unfunded_bytes_count_at_both_admission_points(self):
        for field, reason in (("availableBeforeBytes", "capacity_before"),
                              ("availableAfterBytes", "capacity_after")):
            expected, packet = fixture()
            boundary = (258 + 32 + 100) * GIB if field.endswith("BeforeBytes") else 132 * GIB
            packet["pool"][field] = boundary
            self.check(expected, packet)
            packet["pool"][field] -= 1
            with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                self.check(expected, packet)

    def test_no_retained_record_can_be_dropped_or_aliased(self):
        expected, packet = fixture()
        del packet["reservations"]["retained-test"]
        with self.assertRaisesRegex(ValueError, "^reservation_inventory$"):
            self.check(expected, packet)
        expected, packet = fixture()
        expected["reservations"] = {}
        with self.assertRaisesRegex(ValueError, "^reservation_count$"):
            self.check(expected, packet)

    def test_a_different_expected_document_does_not_match_the_packet(self):
        expected, packet = fixture()
        self.check(expected, packet)
        with self.assertRaisesRegex(ValueError, "^expected_binding$"):
            gate.validate(encode(expected) + b" ", expected, packet, NOW)

    def test_typed_boundaries_refuse_json_shapes_before_later_field_access(self):
        # These are the validator's shared input contract, including values
        # that compare/iterate like the expected type in ordinary Python.
        for function, value, reason in (
            (lambda value: gate.shape(value, "key"), ["key"], "shape"),
            (gate.text, 123, "text"), (gate.text, "x" * 257, "text"),
            (gate.digest, 123, "digest"), (gate.filesystem_uuid, 123, "filesystem_uuid"),
            (gate.identity, {"device": 8, "inode": 1}, "device"),
            (gate.number, 2**63, "number"),
        ):
            with self.subTest(reason=reason, value=value):
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    function(value)
        expected, packet = fixture()
        expected["reservations"] = list(expected["reservations"])
        with self.assertRaisesRegex(ValueError, "^reservation_count$"):
            self.check(expected, packet)
        expected, packet = fixture()
        packet["reservations"] = list(packet["reservations"])
        with self.assertRaisesRegex(ValueError, "^reservation_inventory$"):
            self.check(expected, packet)
        expected, packet = fixture()
        packet["volumes"]["blobs"]["phases"]["reserved"]["extents"] = {
            "0": packet["volumes"]["blobs"]["phases"]["reserved"]["extents"][0]}
        with self.assertRaisesRegex(ValueError, "^extent_count$"):
            self.check(expected, packet)

    def test_installed_kernel_release_may_include_a_build_suffix(self):
        expected, packet = fixture()
        expected["kernelRelease"] = "fixture-kernel+build"
        for role in ("blobs", "journal"):
            packet["volumes"][role]["prevention"]["kernelRelease"] = expected["kernelRelease"]
        self.check(expected, packet)

    def test_closed_shape_at_every_nested_object(self):
        expected, packet = fixture()
        def objects(value):
            if type(value) is dict:
                yield value
                for nested in list(value.values()):
                    yield from objects(nested)
            elif type(value) is list:
                for nested in value:
                    yield from objects(nested)
        # Dynamic reservation IDs are an inventory, not fixed object fields.
        for value in list(objects(expected)) + list(objects(packet)):
            if value in (expected["reservations"], packet["reservations"]):
                continue
            value["unexpected"] = True
            with self.assertRaises(ValueError):
                self.check(expected, packet)
            del value["unexpected"]

    def test_phase_inventory_duplicate_loop_and_final_accounting(self):
        expected, packet = fixture()
        del packet["volumes"]["blobs"]["phases"]["trimmed"]
        with self.assertRaisesRegex(ValueError, "^shape$"):
            self.check(expected, packet)
        expected, packet = fixture()
        packet["volumes"]["journal"]["mount"].update(sourceDevice="/dev/loop0", sourceMajorMinor="7:0")
        with self.assertRaisesRegex(ValueError, "^loop_device$"):
            self.check(expected, packet)
        expected, packet = fixture()
        packet["reservations"]["obsync-blobs"]["allocatedAfterBytes"] -= 1
        with self.assertRaisesRegex(ValueError, "^allocation_ledger$"):
            self.check(expected, packet)

    def test_cli_reads_only_two_explicit_private_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected, packet = fixture()
            for role, count, base in (("blobs", 800, GIB), ("journal", 7, 301 * GIB)):
                for observation in packet["volumes"][role]["phases"].values():
                    fragment(observation, count, base)
            self.check(expected, packet)
            paths = (root / "expected.json", root / "evidence.json")
            for path, value in zip(paths, (expected, packet)):
                path.write_bytes(encode(value))
                path.chmod(0o600)
            output = io.StringIO()
            with patch("sys.argv", ["gate", *map(str, paths)]), patch.object(gate.time, "time", return_value=NOW), redirect_stdout(output), patch.object(gate, "load", wraps=gate.load) as loading:
                self.assertEqual(gate.main(), 0)
            self.assertEqual([call.args for call in loading.call_args_list],
                             [(paths[0], 64 * 1024), (paths[1], 16 * 1024**2)])
            self.assertFalse(json.loads(output.getvalue())["activationAuthorized"])
            self.assertNotIn(directory, output.getvalue())
            paths[1].write_text('{"privateMarker":"NOT_FOR_OUTPUT"}')
            output = io.StringIO()
            with patch("sys.argv", ["gate", *map(str, paths)]), redirect_stdout(output):
                self.assertEqual(gate.main(), 1)
            self.assertEqual(output.getvalue(), "reserved storage evidence: refused\n")

    def test_input_boundary_is_bounded_private_regular_and_not_a_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input.json"
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "input_permissions"):
                gate.load(path)
            path.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                gate.load(link)
            fifo = root / "fifo.json"
            os.mkfifo(fifo, 0o600)
            # A removed nonblocking-open guard must fail promptly under the
            # subprocess deadline, never hang the mutation/test runner.
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/validate_reserved_storage_evidence.py"),
                                     str(fifo), str(path)], capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "reserved storage evidence: refused\n")
            for payload, reason in ((b'x' * (64 * 1024 + 1), "input_file"),
                                    (b'{"key":1,"key":2}', "duplicate_key"),
                                    (b'{"value":NaN}', "json_constant")):
                path.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, reason):
                    gate.load(path)

    def test_each_input_budget_checks_stat_and_reads_at_most_limit_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "growing.json"
            real_stat, real_fdopen = gate.os.fstat, gate.os.fdopen
            for limit in (64 * 1024, 16 * 1024**2):
                reads = []
                class Reader:
                    def __init__(self, fd, mode):
                        self.stream = real_fdopen(fd, mode)
                    def __enter__(self):
                        self.stream.__enter__()
                        return self
                    def __exit__(self, *args):
                        return self.stream.__exit__(*args)
                    def fileno(self):
                        return self.stream.fileno()
                    def read(self, size=-1):
                        reads.append(size)
                        # Refuse an unbounded mutant before it can allocate.
                        self_test.assertEqual(size, limit + 1)
                        return self.stream.read(size)
                self_test = self
                path.write_bytes(b'{}' + b' ' * (limit - 2))
                path.chmod(0o600)
                with patch.object(gate.os, "fdopen", side_effect=Reader):
                    self.assertEqual(gate.load(path, limit)[1], {})
                    self.assertEqual(reads, [limit + 1])
                    reads.clear()
                    path.write_bytes(b'{}' + b' ' * (limit - 1))
                    with self.assertRaisesRegex(ValueError, "^input_file$"):
                        gate.load(path, limit)
                    self.assertEqual(reads, [])
                    path.write_bytes(b'{}')
                    def grow_after_stat(fd):
                        before = real_stat(fd)
                        path.write_bytes(b'{}' + b' ' * (limit - 1))
                        return before
                    with patch.object(gate.os, "fstat", side_effect=grow_after_stat):
                        with self.assertRaisesRegex(ValueError, "^input_size$"):
                            gate.load(path, limit)
                    self.assertEqual(reads, [limit + 1])

    def test_opened_input_type_is_checked_independently_of_reported_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{}')
            path.chmod(0o600)
            real_stat = gate.os.fstat
            def nonregular_metadata(fd):
                fields = list(real_stat(fd))
                fields[0] = stat.S_IFIFO | 0o600
                return os.stat_result(fields)
            with patch.object(gate.os, "fstat", side_effect=nonregular_metadata):
                with self.assertRaisesRegex(ValueError, "^input_file$"):
                    gate.load(path)


if __name__ == "__main__":
    unittest.main()
