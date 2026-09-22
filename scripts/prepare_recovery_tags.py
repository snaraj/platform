#!/usr/bin/env python3
"""Owner command: prepare exactly the missing annotated platform release tags.

Issue #375 keeps release-tag creation out of CI: the publisher and the recovery
workflow both refuse until the owner's annotated tag already exists, so a
compromised workflow cannot mint release history. That control is unchanged
here. This command runs on the owner's machine, with the owner's credentials,
and refuses outright inside a hosted runner. What it removes is the
hand-written heredoc that produced ten tags by hand during the issue #317
incident — one of which was rejected afterwards for a byte the operator could
not see.

The plan is derived from the immutable tag ledger by
``scripts/ci/release_backlog.py`` (the same derivation the watchdog uses), and
every object this command is about to create is checked against the
publisher's own validators before a single ref is pushed:

* ``--head`` accepts only a commit ``refs/remotes/<remote>/main`` already
  contains, so an operator-supplied head can never bind a side branch into a
  ledger the ruleset then keeps forever;
* the target must be the exact untagged first-parent main commit the ledger
  derives, so a tag can never land on a non-first-parent or skipped commit;
* the tagger identity must be the release tagger constant;
* the tagger instant must equal the source commit's committer instant;
* the message must be the exact ``Platform release <tag> from <sha>`` text; and
* an already-present tag that disagrees with any of the above stops the run
  instead of being reused, updated, or replaced.

The command never deletes, moves, or force-updates a ref, and never touches a
Release. Draining the published backlog afterwards remains the recovery
workflow's job.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "prepare_recovery_backlog",
    Path(__file__).resolve().parent / "ci" / "release_backlog.py",
)
B = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = B
_spec.loader.exec_module(B)
C = B.C

# A hosted runner never holds this authority. The workflow contract already
# refuses to publish without an owner-prepared tag; this is the same refusal
# stated where the tag would actually be created.
CI_MARKERS = ("GITHUB_ACTIONS", "CI", "GITHUB_WORKFLOW", "RUNNER_OS")
TAG_FORMAT = (
    "%(objecttype)%00%(*objecttype)%00%(tag)%00%(taggername)%00"
    "%(taggeremail)%00%(taggerdate:iso-strict)%00%(contents)%00%(*objectname)%00"
)


# Ambient Git variables silently redirect which repository, index, or
# configuration a command sees, and an exported author/committer identity
# overrides the tagger this command must pin. Transport variables are left
# alone: the owner's push credential reaches Git through them.
REDIRECTING_VARIABLES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
)


def environment(**pins: str) -> dict[str, str]:
    """The only Git environment this command runs under."""
    values = {
        name: value
        for name, value in os.environ.items()
        if name not in REDIRECTING_VARIABLES
        and not name.startswith(("GIT_CONFIG", "GIT_AUTHOR_", "GIT_COMMITTER_"))
    }
    values.update(pins)
    return values


def git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
        env=environment(),
    )
    return result.stdout.strip()


def tag_records(repository: Path, tag: str) -> tuple[dict, dict] | None:
    """Rebuild the REST ref/tag records from the local object, or report absence.

    Reusing the REST record shape means the local self-check runs the very same
    ``validate_tag_record`` the recovery workflow will run against GitHub's copy
    of this object, rather than a second, weaker local opinion of it.
    """
    raw = subprocess.run(
        ["git", "-C", str(repository), "for-each-ref", "--count=1",
         "--format=" + TAG_FORMAT, f"refs/tags/{tag}"],
        check=True, capture_output=True, timeout=120, env=environment(),
    ).stdout
    if not raw:
        return None
    if not raw.endswith(b"\0\n"):
        raise C.ContractError(f"local tag {tag} metadata is not bounded")
    fields = tuple(field.decode("utf-8") for field in raw[:-2].split(b"\0"))
    if len(fields) != 8:
        raise C.ContractError(f"local tag {tag} metadata is incomplete")
    (object_type, peeled_type, name, tagger_name, tagger_email, tagger_date,
     message, source_sha) = fields
    object_sha = git(repository, "rev-parse", f"refs/tags/{tag}")
    ref_record = {
        "ref": f"refs/tags/{tag}",
        "object": {"type": object_type, "sha": object_sha},
    }
    tag_record = {
        "sha": object_sha,
        "tag": name,
        "object": {"type": peeled_type, "sha": source_sha},
        "message": message,
        "tagger": {
            "name": tagger_name,
            "email": tagger_email.strip("<>"),
            "date": tagger_date,
        },
    }
    return ref_record, tag_record


def verify(repository: Path, edge) -> None:
    """Prove one present tag object is exactly what the publisher will accept."""
    records = tag_records(repository, edge.tag)
    if records is None:
        raise C.ContractError(f"tag {edge.tag} is absent after preparation")
    C.validate_tag_record(
        *records,
        tag=edge.tag,
        source_sha=edge.source_sha,
        message=edge.message,
        tagger_name=C.RELEASE_TAGGER_NAME,
        tagger_email=C.RELEASE_TAGGER_EMAIL,
        tagger_date=edge.source_date,
    )


def create(repository: Path, edge) -> None:
    """Create the annotated object with git's own canonical message encoding."""
    subprocess.run(
        ["git", "-C", str(repository), "tag", "-a", "-m", edge.message,
         edge.tag, edge.source_sha],
        check=True, capture_output=True, text=True, timeout=120,
        env=environment(
            GIT_COMMITTER_NAME=C.RELEASE_TAGGER_NAME,
            GIT_COMMITTER_EMAIL=C.RELEASE_TAGGER_EMAIL,
            GIT_COMMITTER_DATE=edge.source_date,
        ),
    )


def prepare(repository: Path, head: str, *, push: bool, remote: str,
            stream=sys.stdout) -> int:
    """Print the plan; with ``push`` create and publish only the missing tags."""
    for marker in CI_MARKERS:
        if os.environ.get(marker):
            raise C.ContractError(
                "release tags are prepared by the owner, never in CI (issue #375)"
            )
    head_sha = B.resolve(repository, head)
    # ``--head`` is operator-supplied and every tag this run creates is accepted
    # by the immutable ruleset forever. Only history the protected branch
    # already carries may be tagged; an absent tracking ref refuses here too.
    if subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor",
         head_sha, f"refs/remotes/{remote}/main"],
        capture_output=True, text=True, timeout=120, env=environment(),
    ).returncode:
        raise C.ContractError(
            f"head {head_sha} is not an ancestor of refs/remotes/{remote}/main"
        )
    # Deriving the plan walks the whole post-floor ledger first, so an already
    # present tag is either exact — in which case it is a ledger boundary and
    # this plan starts after it — or it stops the run right here. A disagreeing
    # tag is never repaired: the ruleset makes it immutable, so what the
    # operator needs is the refusal, not a second write.
    edges = B.plan(repository, head_sha)
    print(f"Head: {head_sha}", file=stream)
    print(f"Ledger edges pending a tag: {len(edges)}", file=stream)
    for edge in edges:
        print(f"  {edge.tag}  {edge.source_sha}  {edge.fragment_path}", file=stream)
    if not push:
        print("\nPlan only; re-run with --push to create and push these tags.",
              file=stream)
        return 0
    for edge in edges:
        create(repository, edge)
        verify(repository, edge)
    # Re-deriving the ledger over the newly created refs re-runs every ordering,
    # ancestry, one-fragment and metadata rule across the whole post-floor
    # ledger. Nothing is pushed until that complete walk accepts them.
    B.ledger(repository)
    for edge in edges:
        git(repository, "push", remote, f"refs/tags/{edge.tag}:refs/tags/{edge.tag}")
        print(f"pushed {edge.tag}", file=stream)
    print(f"\nPrepared {len(edges)} tag(s).", file=stream)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--head", default="origin/main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args(argv)
    try:
        return prepare(args.repository, args.head, push=args.push,
                       remote=args.remote)
    except (C.ContractError, KeyError, TypeError, ValueError, OSError,
            subprocess.SubprocessError) as error:
        print(f"PREPARE_TAGS_DENIED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
