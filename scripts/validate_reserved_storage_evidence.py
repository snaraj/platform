#!/usr/bin/env python3
"""Check a private, operator-observed qualification packet; never inspect a host.

Input paths name only the two JSON documents. Paths *inside* them are compared,
never opened. A passing result is evidence consistency, not observation,
allocation authority, physical isolation, or application readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PROFILE = "reserved-file-ext4-v1"
CLASS = "local-pie-ssd-reserved"
ROLES = {"blobs": 250 * 1024**3, "journal": 4 * 1024**3}
PHASES = ("reserved", "formatted", "restarted", "trimmed")
MAX_INPUT = 64 * 1024
MAX_AGE = 15 * 60


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), "shape")
    return value


def number(value, minimum=0):
    need(type(value) is int and minimum <= value <= 2**63 - 1, "number")
    return value


def text(value):
    need(type(value) is str and 0 < len(value) <= 256 and
         re.fullmatch(r"[A-Za-z0-9_./:+-]+", value) is not None, "text")
    return value


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
         and value != "0" * 64, "digest")


def same(value, expected):
    # Python considers False == 0 and True == 1; private evidence does not.
    return json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)


def filesystem_uuid(value):
    need(type(value) is str and re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None,
        "filesystem_uuid")
    need(value.replace("-", "") != "0" * 32, "filesystem_uuid")


def identity(value):
    shape(value, "device inode")
    need(type(value["device"]) is str and
         re.fullmatch(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)", value["device"]) is not None, "device")
    number(value["inode"], 1)
    return value["device"], value["inode"]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_key")
        result[key] = value
    return result


def load(path):
    # No following a link, and no unbounded read before a size check. Checking
    # the opened fd also rejects replacement by a non-regular input object.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_INPUT, "input_file")
        need(stat.S_IMODE(info.st_mode) & 0o077 == 0, "input_permissions")
        payload = stream.read(MAX_INPUT + 1)
        need(len(payload) <= MAX_INPUT, "input_size")
    return payload, json.loads(payload, object_pairs_hook=unique_object,
                               parse_constant=lambda _: need(False, "json_constant"))


def allocation(observation, expected_identity, size):
    shape(observation, "identity sizeBytes allocatedBytes extents")
    need(identity(observation["identity"]) == expected_identity, "backing_identity")
    need(number(observation["sizeBytes"], 1) == size, "backing_size")
    need(number(observation["allocatedBytes"]) >= size, "physical_allocation")
    extents = observation["extents"]
    need(type(extents) is list and 1 <= len(extents) <= 256, "extent_count")
    cursor = 0
    physical = []
    for extent in extents:
        shape(extent, "logical physical length state")
        offset = number(extent["logical"])
        start = number(extent["physical"], 1)
        length = number(extent["length"], 1)
        need(extent["state"] in ("written", "unwritten"), "extent_state")
        need(offset == cursor, "extent_coverage")
        need(all(start + length <= low or start >= high for low, high in physical),
             "extent_alias")
        physical.append((start, start + length))
        cursor += length
    need(cursor == size, "extent_coverage")


def validate(expected_bytes, expected, packet, now=None):
    now = int(time.time()) if now is None else now
    shape(expected, "schema profile node poolUuid poolDevice kernelRelease recoveryDecisionSha256 hostReserveBytes hostReserveInodes reservations volumes")
    shape(packet, "schema profile expectedSha256 capturedAt rawEvidenceSha256 pool reservations volumes recovery")
    need(type(expected["schema"]) is int and expected["schema"] == 1 and
         type(packet["schema"]) is int and packet["schema"] == 1, "schema")
    need(expected["profile"] == packet["profile"] == PROFILE, "profile")
    need(packet["expectedSha256"] == hashlib.sha256(expected_bytes).hexdigest(), "expected_binding")
    digest(packet["rawEvidenceSha256"])
    need(0 <= now - number(packet["capturedAt"]) <= MAX_AGE, "freshness")
    for key in ("node", "poolUuid", "poolDevice", "kernelRelease"):
        text(expected[key])
    filesystem_uuid(expected["poolUuid"])
    digest(expected["recoveryDecisionSha256"])
    reserve = number(expected["hostReserveBytes"], 1)
    inode_reserve = number(expected["hostReserveInodes"], 1)
    pool = shape(packet["pool"], "uuid device filesystem node capacityBytes availableBeforeBytes availableAfterBytes availableBeforeInodes availableAfterInodes inventoryComplete")
    need(pool["uuid"] == expected["poolUuid"] and pool["device"] == expected["poolDevice"]
         and pool["node"] == expected["node"] and pool["filesystem"] == "ext4", "pool_identity")
    need(pool["inventoryComplete"] is True, "ledger_complete")
    capacity = number(pool["capacityBytes"], 1)
    before = number(pool["availableBeforeBytes"])
    after = number(pool["availableAfterBytes"])
    need(before <= capacity and after <= capacity, "pool_capacity")
    before_inodes = number(pool["availableBeforeInodes"])
    after_inodes = number(pool["availableAfterInodes"])
    need(type(expected["reservations"]) is dict and
         2 <= len(expected["reservations"]) <= 64, "reservation_count")
    need(type(packet["reservations"]) is dict and
         set(packet["reservations"]) == set(expected["reservations"]), "reservation_inventory")
    identities = set()
    additional = outstanding = allocated_before_total = allocated_after_total = 0
    for key, reservation in expected["reservations"].items():
        text(key)
        shape(reservation, "identity reservedBytes")
        ident = identity(reservation["identity"])
        need(ident[0] == expected["poolDevice"] and ident not in identities, "reservation_identity")
        identities.add(ident)
        reserved = number(reservation["reservedBytes"], 1)
        observed = shape(packet["reservations"][key], "identity allocatedBeforeBytes allocatedAfterBytes")
        need(identity(observed["identity"]) == ident, "reservation_binding")
        allocated_before = number(observed["allocatedBeforeBytes"])
        allocated_after = number(observed["allocatedAfterBytes"])
        need(allocated_before <= capacity and allocated_after <= capacity, "reservation_allocation")
        # Existing allocations already reduce available space. Charge every
        # unfunded byte of ALL retained reservations too; never charge one
        # inode twice, and never infer zero liability from an absent mount.
        additional += max(0, reserved - allocated_before)
        outstanding += max(0, reserved - allocated_after)
        allocated_before_total += allocated_before
        allocated_after_total += allocated_after
    need(allocated_before_total <= capacity - before and
         allocated_after_total <= capacity - after, "ledger_used_bytes")
    need(additional + reserve <= before, "capacity_before")
    need(outstanding + reserve <= after, "capacity_after")
    need(before_inodes >= inode_reserve + 2 and after_inodes >= inode_reserve, "pool_inodes")
    shape(expected["volumes"], "blobs journal")
    shape(packet["volumes"], "blobs journal")
    filesystem_ids = {expected["poolUuid"]}
    mount_devices = set()
    for role, claim_bytes in ROLES.items():
        config = shape(expected["volumes"][role], "backingFile filesystemUuid imageBytes minimumFreeInodes")
        name = "obsync-" + role
        need(config["backingFile"] == "/var/lib/obsync-reserved/" + name + ".img", "backing_path")
        filesystem_uuid(config["filesystemUuid"])
        need(config["filesystemUuid"] not in filesystem_ids, "filesystem_identity")
        filesystem_ids.add(config["filesystemUuid"])
        size = number(config["imageBytes"], 1)
        need(size > claim_bytes, "filesystem_overhead")
        min_inodes = number(config["minimumFreeInodes"], 1)
        need(name in expected["reservations"], "volume_reservation")
        reservation = expected["reservations"][name]
        need(reservation["reservedBytes"] == size, "reserved_size")
        volume = shape(packet["volumes"][role], "backing ownership phases mount fallback prevention")
        need(volume["backing"] == config["backingFile"], "backing_binding")
        need(same(volume["ownership"], {
            "uid": 0, "gid": 0, "mode": "0600", "links": 1, "type": "regular",
            "ancestors": "root-owned-no-links-no-write", "acl": "none",
            "workloadHolePunch": "denied",
        }), "backing_ownership")
        phases = shape(volume["phases"], " ".join(PHASES))
        for phase in PHASES:
            allocation(phases[phase], identity(reservation["identity"]), size)
        need(packet["reservations"][name]["allocatedAfterBytes"] ==
             phases["trimmed"]["allocatedBytes"], "allocation_ledger")
        mount = shape(volume["mount"], "target filesystem uuid sourceDevice sourceMajorMinor backingIdentity flags topology uid gid mode acl usableBytes freeInodes")
        need(mount["target"] == "/mnt/local-pie-ssd-reserved/" + name and
             mount["filesystem"] == "ext4" and mount["uuid"] == config["filesystemUuid"], "mount_identity")
        need(type(mount["sourceDevice"]) is str and
             re.fullmatch(r"/dev/loop(?:0|[1-9][0-9]*)", mount["sourceDevice"]) is not None, "loop_source")
        need(mount["sourceMajorMinor"] == "7:" + mount["sourceDevice"][9:] and
             mount["sourceMajorMinor"] not in mount_devices, "loop_device")
        mount_devices.add(mount["sourceMajorMinor"])
        need(identity(mount["backingIdentity"]) == identity(reservation["identity"]), "loop_backing")
        need(mount["flags"] == ["rw", "nodev", "nosuid", "noexec", "nodiscard"] and
             mount["topology"] == "exact-no-bind-no-nested-no-links", "mount_flags")
        need(type(mount["uid"]) is int and type(mount["gid"]) is int and
             mount["uid"] == mount["gid"] == 65532 and
             mount["mode"] == "0700" and mount["acl"] == "none", "mount_ownership")
        need(claim_bytes <= number(mount["usableBytes"]) <= size and
             number(mount["freeInodes"]) >= min_inodes, "usable_capacity")
        need(same(volume["fallback"], {
            "uid": 0, "gid": 0, "mode": "0000", "acl": "none", "layout": "absent",
            "workloadWrite": "denied", "ancestors": "root-owned-no-links-no-write",
        }), "fallback")
        prevention = shape(volume["prevention"], "kernelRelease mechanismSha256 formatDiscard loopDiscard loopZeroUnmap restartEnforcement explicitTrim")
        need(prevention["kernelRelease"] == expected["kernelRelease"], "kernel_binding")
        digest(prevention["mechanismSha256"])
        need(prevention["formatDiscard"] == "disabled" and
             prevention["loopDiscard"] == "blocked" and
             prevention["loopZeroUnmap"] == "blocked" and
             prevention["restartEnforcement"] == "verified" and
             prevention["explicitTrim"] == "blocked-reservation-unchanged", "trim_prevention")
    need(same(packet["recovery"], {
        "missingMount": "refused", "wrongBacking": "refused", "secondConsumer": "refused",
        "restartDurability": "verified", "offlineRestore": "verified", "quarantineRecovery": "verified",
        "reconciler": "suspended", "deploymentReady": False,
    }), "recovery")
    return {"profile": PROFILE, "evidenceConsistency": "pass", "activationAuthorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        expected_bytes, expected = load(args.expected)
        _, packet = load(args.evidence)
        result = validate(expected_bytes, expected, packet)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        # Do not echo private paths, identifiers or invalid input values.
        print("reserved storage evidence: refused")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
