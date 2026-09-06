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
WORKFLOW = ".github/workflows/platform-release.yml@refs/heads/main"


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
    epoch = 1 if version(tag) < version(FIRST_V2_TAG) else 2
    name = OLD_REPOSITORY if epoch == 1 else NEW_REPOSITORY
    asset = f"platform-release-identity.v{epoch}.json"
    return {"repository": name, "schema": f"https://snaraj.dev/schemas/platform-release-identity/v{epoch}",
            "asset": asset, "bundle": asset + ".sigstore.json",
            "subject": f"https://github.com/{name}/{WORKFLOW}", "version": epoch,
            "selector_digest": FROZEN_SELECTOR_DIGEST, "selector_source": FROZEN_SELECTOR_SOURCE}


def publication(name: str, object_id: object, tag: str, base_tag: str, base_sha: str) -> dict[str, object]:
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
    # The exact-next check and closed epoch boundary imply terminal-v1 ->
    # first-v2 and v2 -> v2. No second, redundant predecessor exception exists.
    return selected


def validate_identity(evidence: dict) -> None:
    """Keep v1 bytes intact; its existing signed fields bind the terminal edge."""
    tag = evidence["tag"]["name"]
    selected = identity(tag)
    if (evidence.get("schema"), evidence.get("repository")) != (selected["schema"], selected["repository"]):
        raise ValueError("signed repository and release epoch disagree")
    if selected["version"] == 2:
        repository(evidence["repository"], evidence.get("repository_id"))
    predecessor = evidence["predecessor"]
    if next_tag(predecessor["tag"]) != tag:
        raise ValueError("signed release epoch has a foreign predecessor")
    if tag == TERMINAL_V1_TAG and predecessor != {"tag": CHECKPOINT_TAG, "peeled_commit": CHECKPOINT_SOURCE}:
        raise ValueError("terminal v1 identity has a foreign checkpoint")
    if version(tag) >= version(TERMINAL_V1_TAG):
        selector = evidence["selector"]
        if (selector["digest"], selector["provenance"]["source_sha"]) != (FROZEN_SELECTOR_DIGEST, FROZEN_SELECTOR_SOURCE):
            raise ValueError("retired selector lineage changed")


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
    parser.add_argument("--git-remote")
    parser.add_argument("--repository")
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--base-tag")
    parser.add_argument("--base-sha")
    parser.add_argument("--repository-json", type=Path)
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
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
            value = publication(args.repository, args.repository_id, args.tag, args.base_tag, args.base_sha)
        else:
            value = identity(args.tag)
        if args.source_sha is not None:
            if not publishing or re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None:
                raise ValueError("selector source check requires an exact publication")
            result = subprocess.run(
                ["git", "diff", "--exit-code", FROZEN_SELECTOR_SOURCE, args.source_sha,
                 "--", "cmd/platform-release-selector", "internal/releaseselector", "go.mod"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False,
            )
            if result.returncode != 0:
                raise ValueError("frozen selector source changed or is unavailable")
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
