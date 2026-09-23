#!/usr/bin/env python3
"""Closed release identities for the existing repository's one name change.

Issue #395 removed the hand-frozen backlog table that used to live here. Every
fact it transcribed — source, tree, first parent, fragment path and SHA-256,
the original main-CI and CodeQL run IDs, the workflow inventory — is already
bound by an owner-prepared annotated tag under the immutable tag ruleset, and
is re-derived at run time from git (`release_backlog.Edge`) and from the API
(`platform_release_recovery.selection`). A table row was a transcription of
those facts, a hand edit per backlog edge, and a second place for them to
disagree.

What stays here is the epoch policy no tag can carry: which repository name,
schema, asset names and signing subject a tag belongs to, and the relation
between a publication's SOURCE and the EXECUTOR that published it. This module
is deliberately git-free and network-free apart from the one bounded repository
lookup `git_remote` makes, so the ancestry fact the recovery relation needs is
proved by the caller and passed in.
"""

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


def release_target(source_sha: str, *, recovering: bool) -> str:
    """The `target_commitish` a publication's own route produces.

    An ordinary publication creates the tag ref itself and targets the exact
    source. A recovery publication creates the Release against an annotated tag
    the owner already pushed, with no `target_commitish` in the request, so
    GitHub answers with the default-branch hint. The real source is bound by
    the tag object and its peeled commit either way; this only says which of
    the two hints an exact record may carry.
    """
    if recovering:
        return "main"
    if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("release target source is malformed")
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


def identity(tag: str, *, recovering: bool = False) -> dict[str, object]:
    """Select one tag's epoch policy, and for v4 its publisher relation.

    `recovering` is not looked up here any more: a table lookup made the
    publisher relation a property of the tag NUMBER, which is exactly what the
    backlog kept editing. It is now the caller's derived fact — the executor
    relation for a publication, or the signed `execution.source_sha` for an
    identity already published — and `validate_execution` refuses evidence
    whose recorded publisher fields disagree with it.
    """
    if not isinstance(recovering, bool):
        raise ValueError("publisher relation must be an explicit boolean")
    epoch = (1 if version(tag) < version(FIRST_V2_TAG) else
             2 if version(tag) < version(FIRST_V3_TAG) else
             3 if version(tag) < version(FIRST_V4_TAG) else 4)
    if recovering and epoch != 4:
        raise ValueError("only a v4 release epoch has a recovery publisher")
    name = OLD_REPOSITORY if epoch == 1 else NEW_REPOSITORY
    asset = f"platform-release-identity.v{epoch}.json"
    value = {"repository": name, "schema": f"https://snaraj.dev/schemas/platform-release-identity/v{epoch}",
            "asset": asset, "bundle": asset + ".sigstore.json",
            "subject": f"https://github.com/{name}/{WORKFLOW}", "version": epoch}
    if epoch < 3:
        value.update(selector_digest=FROZEN_SELECTOR_DIGEST,
                     selector_source=FROZEN_SELECTOR_SOURCE)
    if epoch == 4:
        workflow = RECOVERY_WORKFLOW if recovering else WORKFLOW.split("@", 1)[0]
        value.update(
            publisher_workflow=workflow,
            publisher_event="workflow_dispatch" if recovering else "workflow_run",
            subject=f"https://github.com/{name}/{workflow}@refs/heads/main",
        )
    return value


def publication(name: str, object_id: object, tag: str, base_tag: str, base_sha: str,
                source_sha: str | None = None, *, recovering: bool = False) -> dict[str, object]:
    """Authorize the name/epoch only after the caller derives the exact edge."""
    repository(name, object_id)
    if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
        raise ValueError("publication predecessor source is malformed")
    selected = identity(tag, recovering=recovering)
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
        if source_sha == TERMINAL_V3_SOURCE or base_sha == source_sha:
            raise ValueError("v4 publication cannot republish its own predecessor")
    # The exact-next check and closed epoch boundary imply terminal-v1 ->
    # first-v2 and v2 -> v2. No second, redundant predecessor exception exists.
    return selected


def validate_identity(evidence: dict, *, executor_descends: bool | None = None) -> None:
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
        validate_execution(evidence, executor_descends=executor_descends)


def recovering_identity(evidence: dict) -> bool:
    """The publisher relation a v4 identity's own signed fields already state.

    The executor is either the source itself (the ordinary `workflow_run`
    publisher, which runs at the commit it releases) or a different commit (a
    recovery dispatch draining behind main). Nothing else can be true of one
    payload, so this is a derivation rather than a claim, and `validate_execution`
    then requires the recorded publisher workflow and event to match it.
    """
    execution = evidence.get("execution")
    source = evidence.get("source")
    if not isinstance(execution, dict) or not isinstance(source, dict):
        raise ValueError("publication execution or source fields are missing")
    return execution.get("source_sha") != source.get("merge_sha")


def validate_execution(evidence: dict, *, executor_descends: bool | None = None) -> None:
    """Bind the executor to its source by RELATION rather than membership.

    Ordinary publication is executor == source: the `workflow_run` publisher
    runs at the very commit it releases, so its tree and main-CI receipt are the
    source's own. Recovery publication is executor != source, and the only
    executor it admits is a LATER commit on protected main's own first-parent
    line — the shape a drain running behind main always has, and the shape a
    REPLAY of an old workflow never has, because every earlier source is an
    ancestor of the executor rather than a first-parent descendant of it. The
    terminal v3 source is refused by that construction alone: it precedes every
    v4 source, so it can never descend from one. Membership, not reachability:
    a side branch merged into main is an ancestor of main that was never main.

    The relation is a git fact and this module stays git-free, so the caller
    proves it (`platform_release_contract.executor_descends`) and passes it.
    Recovery-shaped evidence with no proof refuses rather than defaulting.
    """
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
    recovering = recovering_identity(evidence)
    if recovering:
        if executor_descends is None:
            raise ValueError("recovery execution needs an ancestry proof")
        if executor_descends is not True:
            raise ValueError("recovery executor is not a later first-parent commit of its source")
    elif (
        execution["tree_sha"] != source["tree_sha"]
        or execution["main_ci"] != evidence["main_ci"]
    ):
        raise ValueError("ordinary publication cannot substitute its executor")
    # The signing subject is a pure function of publisher_workflow, so agreeing
    # on the workflow and the event fixes the subject cosign was given too.
    selected = identity(evidence["tag"]["name"], recovering=recovering)
    publisher = evidence.get("platform_release")
    if (
        not isinstance(publisher, dict)
        or publisher.get("workflow") != selected["publisher_workflow"]
        or publisher.get("event") != selected["publisher_event"]
        or publisher.get("head_sha") != execution["source_sha"]
    ):
        raise ValueError("recorded publisher identity disagrees with the derived relation")


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
    parser.add_argument("--executor-sha")
    parser.add_argument("--recovering", action="store_true", default=False)
    args = parser.parse_args()
    try:
        if args.git_remote is not None:
            if (args.recovering or any(value is not None for key, value in vars(args).items()
                                       if key not in {"git_remote", "recovering"})):
                raise ValueError("Git remote verification cannot carry release inputs")
            print(git_remote(args.git_remote))
            return 0
        # A recovery policy names a DIFFERENT signing subject, so the caller
        # states both commits of the relation and they must actually differ;
        # the ordinary publisher never passes the flag and cannot reach the
        # recovery subject by omitting one of them.
        if args.recovering:
            if args.source_sha is None or args.executor_sha is None:
                raise ValueError("a recovery policy needs its exact source and executor")
            if args.source_sha == args.executor_sha:
                raise ValueError("a recovery policy needs an executor other than its source")
        elif args.executor_sha is not None and args.executor_sha != args.source_sha:
            raise ValueError("an ordinary policy cannot name a foreign executor")
        if args.repository_json is not None:
            record = json.loads(args.repository_json.read_bytes())
            repository(record.get("full_name"), record.get("id"))
            if (record["full_name"], record["id"]) != (args.repository, args.repository_id):
                raise ValueError("repository response and workflow context disagree")
        publishing = any(value is not None for value in (args.repository, args.repository_id, args.base_tag, args.base_sha))
        if publishing:
            if any(value is None for value in (args.repository, args.repository_id, args.base_tag, args.base_sha)):
                raise ValueError("publication epoch inputs are incomplete")
            value = publication(args.repository, args.repository_id, args.tag, args.base_tag,
                                args.base_sha, args.source_sha, recovering=args.recovering)
        else:
            value = identity(args.tag, recovering=args.recovering)
        if args.source_sha is not None and re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None:
            raise ValueError("source check requires an exact publication")
        if args.executor_sha is not None and re.fullmatch(r"[0-9a-f]{40}", args.executor_sha) is None:
            raise ValueError("executor check requires an exact commit")
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
