#!/usr/bin/env python3
"""Closed release identities for the existing repository's one name change."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

OLD_REPOSITORY = "snaraj/website-infrastructure"
NEW_REPOSITORY = "snaraj/platform"
REPOSITORY_ID = 1327645656
CHECKPOINT_TAG = "v0.1.68"
CHECKPOINT_SOURCE = "b4bf0ac19038b1bca43651b601a348f8a84e7163"
FROZEN_SELECTOR_DIGEST = "sha256:c104c4b87f9932f08302fd30454605b3326794097cfbe5d4060db8f9cca5c003"
FROZEN_SELECTOR_SOURCE = "ce8598a9f0b4eca52cff231ed94137926df13c08"
TERMINAL_V2_TAG = "v0.1.77"
TERMINAL_V2_SOURCE = "7b768d56a50f258ff893410c90e0cfd4401441c0"
FIRST_V3_TAG = "v0.1.78"
WORKFLOW = ".github/workflows/platform-release.yml@refs/heads/main"
TERMINAL_V3_TAG = "v0.1.80"
TERMINAL_V3_SOURCE = "4f9b29339fec6ff06b37ecc0024b48cbe857f96f"
RECOVERY_WORKFLOW = ".github/workflows/platform-release-recovery.yml"
# These are published protected-main source/CI records, not caller-selected
# replay inputs or allocated tags. The ordinary ledger derives each next tag.
HISTORICAL_RELEASES = (
    {
        "source_sha": "060c9678e130487b27cdaec395b0f1c5d74b9240",
        "tree_sha": "3ff155f933aba5e0e528d1f30a36357968031917",
        "parent_sha": TERMINAL_V3_SOURCE,
        "fragment_path": "changelog.d/362-obsync-private-boundary.md",
        "fragment_sha256": "efcf3d946e417320cc7d75f724cc862470571946cfe5fa760404a240cd150df1",
        "main_run_id": 34283118915,
        "codeql_run_id": 34283118636,
    },
    {
        "source_sha": "9cd79f1e69cfa00eb5467822831056101629c8f8",
        "tree_sha": "360078458d75927170d39c176479d14af0a58928",
        "parent_sha": "060c9678e130487b27cdaec395b0f1c5d74b9240",
        "fragment_path": "changelog.d/365-obsync-staged-readiness.md",
        "fragment_sha256": "546e5ad23459bd53a94b768668e1faa09ff1500fc1a34b5bf03d98a521d9b44a",
        "main_run_id": 34305321734,
        "codeql_run_id": 34305321809,
    },
    {
        "source_sha": "3b7a0532ba5fe2f10037023f3e26ec5876f8d191",
        "tree_sha": "012b386dacf8dcffde5a78dba9af2897d229859d",
        "parent_sha": "9cd79f1e69cfa00eb5467822831056101629c8f8",
        "fragment_path": "changelog.d/367-reserved-file-storage.md",
        "fragment_sha256": "90e877f38e58ff5e7c7caa564bc2606c2c7138229b544a59c200ba24154e8009",
        "main_run_id": 34638257426,
        "codeql_run_id": 34638258315,
    },
)
HISTORICAL_WORKFLOWS = {
    ".github/workflows/pull-request.yml": "3fe60af5eb1f1e540cb2bbeda9888aa58fb85622f08c75f7246d50eb90c9d552",
    ".github/workflows/codeql.yml": "ecd647fa9c1867ef8fe162a19edf2ec978de8bdd7f8fb5d6beb74760540c91f0",
    ".github/workflows/platform-release.yml": "7964da478567a32ca68418a7b974f2f6dceeb1bddb027cee03bd8f698780aa00",
}


def version(tag: str) -> tuple[int, int, int]:
    if not isinstance(tag, str) or len(tag) > 64:
        raise ValueError("release tag is malformed")
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if match is None:
        raise ValueError("release tag is malformed")
    return tuple(int(part) for part in match.groups())


def next_tag(tag: str) -> str:
    major, minor, patch = version(tag)
    return f"v{major}.{minor}.{patch + 1}"


# The ledger still derives tags. These bounds stop old-name publication after
# the single compatibility release; they do not allocate or create a tag.
TERMINAL_V1_TAG = next_tag(CHECKPOINT_TAG)
FIRST_V2_TAG = next_tag(TERMINAL_V1_TAG)
FIRST_V4_TAG = next_tag(TERMINAL_V3_TAG)


def historical_release(tag: str) -> dict | None:
    candidate = FIRST_V4_TAG
    for source in HISTORICAL_RELEASES:
        if tag == candidate:
            return source
        candidate = next_tag(candidate)
    return None


def release_target(tag: str, source_sha: str) -> str:
    """The historical source is bound by its tag, not a default-target hint."""
    frozen = historical_release(tag)
    if frozen is not None:
        if source_sha != frozen["source_sha"]:
            raise ValueError("recovery target has a foreign source")
        return "main"
    return source_sha


def repository(name: str, object_id: object) -> str:
    """A permitted spelling never authorizes a replacement repository object."""
    if name not in (OLD_REPOSITORY, NEW_REPOSITORY) or type(object_id) is not int or object_id != REPOSITORY_ID:
        raise ValueError("repository name or immutable object identity is foreign")
    return name


def git_remote(url: str) -> str:
    """Bind either exact Git transport to the original, currently named object."""
    names = [name for name in (OLD_REPOSITORY, NEW_REPOSITORY)
             if url in (f"https://github.com/{name}.git", "git" + "@" + f"github.com:{name}.git")]
    if len(names) != 1:
        raise ValueError("Git remote is outside the closed repository URL set")
    name = names[0]
    # A URL allowance alone would also admit a replacement at that name. Use
    # the configured GitHub CLI for one bounded GET, never a credential export.
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "--method", "GET",
         f"repos/{name}", "--jq", "{id, full_name}"],
        capture_output=True, text=True, check=True, timeout=15,
    )
    record = json.loads(result.stdout)
    if not isinstance(record, dict) or repository(record.get("full_name"), record.get("id")) != name:
        raise ValueError("Git remote does not name the current original repository")
    return name


def identity(tag: str) -> dict[str, object]:
    epoch = (1 if version(tag) < version(FIRST_V2_TAG) else
             2 if version(tag) < version(FIRST_V3_TAG) else
             3 if version(tag) < version(FIRST_V4_TAG) else 4)
    name = OLD_REPOSITORY if epoch == 1 else NEW_REPOSITORY
    asset = f"platform-release-identity.v{epoch}.json"
    value = {"repository": name, "schema": f"https://snaraj.dev/schemas/platform-release-identity/v{epoch}",
            "asset": asset, "bundle": asset + ".sigstore.json",
            "subject": f"https://github.com/{name}/{WORKFLOW}", "version": epoch}
    if epoch < 3:
        value.update(selector_digest=FROZEN_SELECTOR_DIGEST,
                     selector_source=FROZEN_SELECTOR_SOURCE)
    if epoch == 4:
        recovering = historical_release(tag) is not None
        workflow = RECOVERY_WORKFLOW if recovering else WORKFLOW.split("@", 1)[0]
        value.update(
            publisher_workflow=workflow,
            publisher_event="workflow_dispatch" if recovering else "workflow_run",
            subject=f"https://github.com/{name}/{workflow}@refs/heads/main",
        )
    return value


def publication(name: str, object_id: object, tag: str, base_tag: str, base_sha: str,
                source_sha: str | None = None) -> dict[str, object]:
    """Authorize the name/epoch only after the caller derives the exact edge."""
    repository(name, object_id)
    if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
        raise ValueError("publication predecessor source is malformed")
    selected = identity(tag)
    if selected["repository"] != name or next_tag(base_tag) != tag:
        raise ValueError("repository and release epoch or predecessor disagree")
    if name == OLD_REPOSITORY:
        if (tag, base_tag, base_sha) != (TERMINAL_V1_TAG, CHECKPOINT_TAG, CHECKPOINT_SOURCE):
            raise ValueError("old-name publication is only the terminal v1 edge")
    if tag == FIRST_V3_TAG and (base_tag, base_sha) != (TERMINAL_V2_TAG, TERMINAL_V2_SOURCE):
        raise ValueError("first v3 publication has a foreign terminal-v2 predecessor")
    if selected["version"] == 4:
        if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
            raise ValueError("v4 publication requires its exact source SHA")
        frozen = historical_release(tag)
        if frozen is not None:
            if (source_sha, base_sha) != (frozen["source_sha"], frozen["parent_sha"]):
                raise ValueError("historical publication source or predecessor is foreign")
        elif source_sha in {entry["source_sha"] for entry in HISTORICAL_RELEASES}:
            raise ValueError("historical source cannot choose another release edge")
    # The exact-next check and closed epoch boundary imply terminal-v1 ->
    # first-v2 and v2 -> v2. No second, redundant predecessor exception exists.
    return selected


def validate_identity(evidence: dict) -> None:
    """Keep v1 bytes intact; its existing signed fields bind the terminal edge."""
    tag = evidence["tag"]["name"]
    selected = identity(tag)
    if (evidence.get("schema"), evidence.get("repository")) != (selected["schema"], selected["repository"]):
        raise ValueError("signed repository and release epoch disagree")
    if selected["version"] >= 2:
        repository(evidence["repository"], evidence.get("repository_id"))
    predecessor = evidence["predecessor"]
    if next_tag(predecessor["tag"]) != tag:
        raise ValueError("signed release epoch has a foreign predecessor")
    if tag == TERMINAL_V1_TAG and predecessor != {"tag": CHECKPOINT_TAG, "peeled_commit": CHECKPOINT_SOURCE}:
        raise ValueError("terminal v1 identity has a foreign checkpoint")
    if selected["version"] < 3 and version(tag) >= version(TERMINAL_V1_TAG):
        selector = evidence["selector"]
        if (selector["digest"], selector["provenance"]["source_sha"]) != (FROZEN_SELECTOR_DIGEST, FROZEN_SELECTOR_SOURCE):
            raise ValueError("retired selector lineage changed")
    if selected["version"] == 4:
        validate_execution(evidence)


def validate_execution(evidence: dict) -> None:
    """Bind current execution separately, only for the finite recovery set."""
    execution = evidence["execution"]
    if not isinstance(execution, dict) or set(execution) != {"source_sha", "tree_sha", "main_ci"}:
        raise ValueError("publication execution fields are foreign")
    for field in ("source_sha", "tree_sha"):
        if not isinstance(execution[field], str) or re.fullmatch(r"[0-9a-f]{40}", execution[field]) is None:
            raise ValueError("publication execution identity is malformed")
    run = execution["main_ci"]
    if (
        not isinstance(run, dict)
        or set(run) != {"conclusion", "event", "head_sha", "ref", "run_attempt", "run_id", "workflow"}
        or run["conclusion"] != "success"
        or run["event"] != "push"
        or run["head_sha"] != execution["source_sha"]
        or run["ref"] != "refs/heads/main"
        or run["workflow"] != ".github/workflows/pull-request.yml"
        or type(run["run_id"]) is not int or run["run_id"] <= 0
        or type(run["run_attempt"]) is not int or run["run_attempt"] <= 0
    ):
        raise ValueError("publication execution main CI is foreign")
    source = evidence["source"]
    frozen = historical_release(evidence["tag"]["name"])
    if frozen is not None:
        if (
            source["merge_sha"] != frozen["source_sha"]
            or source["tree_sha"] != frozen["tree_sha"]
            or evidence["predecessor"]["peeled_commit"] != frozen["parent_sha"]
            or evidence["changelog"] != {
                "fragment_path": frozen["fragment_path"],
                "fragment_sha256": "sha256:" + frozen["fragment_sha256"],
            }
            or evidence["main_ci"]["run_id"] != frozen["main_run_id"]
            or evidence["main_ci"]["run_attempt"] != 1
            or evidence["platform_release"]["run_attempt"] != 1
            or execution["source_sha"] in {entry["source_sha"] for entry in HISTORICAL_RELEASES}
            or execution["source_sha"] == TERMINAL_V3_SOURCE
        ):
            raise ValueError("historical execution or original evidence is foreign")
    elif (
        execution["source_sha"] != source["merge_sha"]
        or execution["tree_sha"] != source["tree_sha"]
        or execution["main_ci"] != evidence["main_ci"]
    ):
        raise ValueError("ordinary publication cannot substitute its executor")


def run_repository(tag: str, record: dict) -> None:
    """Historical old-name records retain compatibility; aliases need object proof."""
    if version(tag) < version(TERMINAL_V1_TAG) and record.get("full_name") == OLD_REPOSITORY and "id" not in record:
        return
    repository(record.get("full_name"), record.get("id"))
    metadata_repository(tag, record.get("full_name"), record.get("id"))


def metadata_repository(tag: str, name: str | None, object_id: object) -> str:
    selected = identity(tag)
    if name is None and object_id is None:
        if selected["version"] != 1:
            raise ValueError("v2 transport requires immutable repository proof")
        return selected["repository"]
    repository(name, object_id)
    if name == OLD_REPOSITORY and selected["version"] != 1:
        raise ValueError("v2 identity cannot use the old repository transport")
    return name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", nargs="?")
    parser.add_argument("--historical-main-run", action="store_true", default=None)
    parser.add_argument("--git-remote")
    parser.add_argument("--repository")
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--base-tag")
    parser.add_argument("--base-sha")
    parser.add_argument("--repository-json", type=Path)
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
        if args.historical_main_run:
            if any(value is not None for key, value in vars(args).items()
                   if key not in {"tag", "historical_main_run"}):
                raise ValueError("historical run lookup accepts only its closed tag")
            frozen = historical_release(args.tag)
            if frozen is None:
                raise ValueError("tag is outside the finite recovery window")
            print(frozen["main_run_id"])
            return 0
        if args.git_remote is not None:
            if any(value is not None for key, value in vars(args).items() if key != "git_remote"):
                raise ValueError("Git remote verification cannot carry release inputs")
            print(git_remote(args.git_remote))
            return 0
        if args.repository_json is not None:
            record = json.loads(args.repository_json.read_bytes())
            repository(record.get("full_name"), record.get("id"))
            if (record["full_name"], record["id"]) != (args.repository, args.repository_id):
                raise ValueError("repository response and workflow context disagree")
        publishing = any(value is not None for value in (args.repository, args.repository_id, args.base_tag, args.base_sha))
        if publishing:
            if any(value is None for value in (args.repository, args.repository_id, args.base_tag, args.base_sha)):
                raise ValueError("publication epoch inputs are incomplete")
            value = publication(args.repository, args.repository_id, args.tag, args.base_tag, args.base_sha, args.source_sha)
        else:
            value = identity(args.tag)
        if args.source_sha is not None and (not publishing or re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None):
            raise ValueError("source check requires an exact publication")
        print(json.dumps(value, sort_keys=True))
        return 0
    except subprocess.SubprocessError:
        print("RELEASE_EPOCH_DENIED: repository lookup failed or timed out")
        return 1
    except (KeyError, TypeError, ValueError, OSError) as error:
        print("RELEASE_EPOCH_DENIED: " + str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
