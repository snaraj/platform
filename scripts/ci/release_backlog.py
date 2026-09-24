#!/usr/bin/env python3
"""Read-only source-release backlog derivation and its daily watchdog.

The backlog is derived from the publisher's own contract rather than
configured beside it: ``plan`` walks the immutable tag ledger exactly as
``platform_release_contract`` does, so the watchdog can never report a release
the publisher would refuse. That shared derivation is the point —
issue #317 exists because a publisher died mid-flight and ten later merges
queued behind it unnoticed for two weeks.

Nothing in this module creates, moves, or deletes a Git ref, a tag, or a
Release, and nothing here dispatches a workflow. Its only write is one GitHub
issue. Publication stays with the tip-only publisher (issue #397), which
publishes a green tip within the hour on its own; an alert here therefore means
the tip stayed red or the publisher refused, and names where to look.

The checkout, the head and the repository object are arguments, not constants,
so the same derivation serves another checkout or another repository without a
copy of this code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "release_backlog_contract",
    Path(__file__).with_name("platform_release_contract.py"),
)
C = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = C
_spec.loader.exec_module(C)

API_ROOT = "https://api.github.com"
# One derivation bound shared by both consumers: a ledger that has drifted
# further than a human could have reviewed is a fault, not a longer report.
MAX_PLAN_EDGES = 64
MAX_UNRELEASED_LOOKBACK = 64
MAX_REQUESTS = 96
MAX_RESPONSE_BYTES = 1 << 20
# The tip publisher reconciles hourly; a green tip still unreleased after this
# long means main stayed red or the publisher refused, both worth a human look.
PENDING_ALERT_HOURS = 6
ISSUE_TITLE = "deploy-assurance[release-backlog]"
ISSUE_LABELS = ("agentic-conversation-requested", "release")
ISSUE_AUTHOR = "github-actions[bot]"
PUBLISHER_WORKFLOW = "platform-release.yml"


@dataclass(frozen=True)
class Pending:
    """The one tip Release main is waiting for: every fragment since the ledger."""

    tag: str
    source_sha: str
    base_tag: str
    base_sha: str
    fragment_paths: tuple[str, ...]
    source_date: str

    def as_dict(self) -> dict[str, object]:
        return {
            "tag": self.tag,
            "source_sha": self.source_sha,
            "base_tag": self.base_tag,
            "base_sha": self.base_sha,
            "fragment_paths": list(self.fragment_paths),
            "source_date": self.source_date,
        }


def resolve(repository: Path, revision: str) -> str:
    """Accept an ordinary revision spelling and pin it to one exact commit.

    Every downstream rule still works on the exact 40-hex SHA; this only spares
    the operator a ``git rev-parse`` in the documented one-line command.
    """
    if not isinstance(revision, str) or not revision or revision.startswith("-"):
        raise C.ContractError("release backlog head revision is malformed")
    resolved = C._git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    return C._exact_commit(repository, resolved or "", "release backlog head SHA")


def ledger(repository: Path) -> tuple:
    """The validated immutable tag ledger; every tag is proved exact here."""
    return C._platform_tag_boundaries(repository)


def plan(repository: Path, head_sha: str) -> tuple[Pending, ...]:
    """Derive the one tip Release the head is waiting for, or none.

    The rule is the publisher's, not a local reimplementation: the range must be
    one contiguous single-parent chain (``_linear_commits`` refuses a merge
    commit or a gap) and it binds every fragment added since the latest tag.
    The pending age is the oldest unreleased commit's, which is how long the
    change has been waiting.
    """
    head_sha = resolve(repository, head_sha)
    boundaries = ledger(repository)
    latest = boundaries[-1]
    if latest.source_sha == head_sha:
        return ()
    commits = C._linear_commits(repository, latest.source_sha, head_sha)
    if len(commits) > MAX_PLAN_EDGES:
        raise C.ContractError("release backlog exceeds its review bound")
    intents = C._release_surface_intents(repository, latest.source_sha, head_sha)
    if not intents:
        return ()
    source_date = C._git(repository, "show", "-s", "--format=%cI", commits[0])
    if not isinstance(source_date, str) or not source_date:
        raise C.ContractError("backlog source commit has no committer date")
    return (
        Pending(
            C.next_version(latest.version).tag,
            head_sha,
            latest.tag,
            latest.source_sha,
            tuple(intent.fragment_path for intent in intents),
            source_date,
        ),
    )


class Reader:
    """Bounded authenticated GETs plus the single issue write, nothing else."""

    def __init__(self, token: str, repository: str):
        if not token or not isinstance(repository, str) or repository.count("/") != 1:
            raise C.ContractError("backlog watchdog needs a token and one repository")
        self.token = token
        self.repository = repository
        self.requests = 0

    def _call(self, path: str, *, method: str = "GET", payload: dict | None = None,
              absent: bool = False) -> dict | list | None:
        if not path.startswith("/") or any(
            value in path for value in ("..", "#", "\\", "\r", "\n")
        ):
            raise C.ContractError("foreign API path")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise C.ContractError("backlog read budget exhausted")
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": C.GITHUB_API_VERSION,
            "User-Agent": "platform-release-backlog",
            "Authorization": f"Bearer {self.token}",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            API_ROOT + path, headers=headers, data=body, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status not in (200, 201):
                    raise C.ContractError("GitHub response was not successful")
                data = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            with error:
                if absent and error.code == 404:
                    return None
                # Never echo an API body, header, or credential into the log.
                raise C.ContractError(
                    f"GitHub request refused with HTTP {error.code}"
                ) from error
        if len(data) > MAX_RESPONSE_BYTES:
            raise C.ContractError("GitHub response exceeds its byte budget")
        return json.loads(data)

    def get(self, path: str, *, absent: bool = False):
        return self._call(path, absent=absent)

    def write(self, path: str, payload: dict, *, method: str):
        if method not in ("POST", "PATCH"):
            raise C.ContractError("backlog watchdog writes only issues")
        return self._call(path, method=method, payload=payload)


def unreleased(boundaries: tuple, api: Reader) -> tuple:
    """Tags newest-first until the first published Release; those are pending.

    A tag whose immutable Release never landed is exactly the state that went
    unnoticed for two weeks. The walk fails closed when no published Release
    appears inside the lookback bound rather than reporting a clean ledger.
    """
    window = boundaries[-MAX_UNRELEASED_LOOKBACK:]
    missing = []
    for boundary in reversed(window):
        record = api.get(
            f"/repos/{api.repository}/releases/tags/{boundary.tag}", absent=True
        )
        if isinstance(record, dict) and record.get("draft") is False:
            missing.reverse()
            return tuple(missing)
        missing.append(boundary)
    raise C.ContractError("no published Release inside the backlog lookback bound")


def publisher_failed(api: Reader) -> bool:
    """True when the newest protected-main publisher attempt did not succeed."""
    runs = api.get(
        f"/repos/{api.repository}/actions/workflows/{PUBLISHER_WORKFLOW}"
        "/runs?branch=main&per_page=1"
    )
    if not isinstance(runs, dict):
        raise C.ContractError("publisher run listing is malformed")
    records = runs.get("workflow_runs")
    if not isinstance(records, list):
        raise C.ContractError("publisher run listing is malformed")
    if not records:
        return False
    record = records[0]
    if not isinstance(record, dict):
        raise C.ContractError("publisher run record is malformed")
    return record.get("status") == "completed" and record.get("conclusion") != "success"


def _age_hours(timestamp: str, now: dt.datetime) -> float:
    moment = dt.datetime.fromisoformat(timestamp)
    if moment.tzinfo is None:
        raise C.ContractError("backlog timestamp has no time zone")
    return (now - moment).total_seconds() / 3600.0


def report(pending: tuple, failed: bool, now: dt.datetime) -> tuple[bool, str]:
    """Render the alert body and decide whether the backlog needs attention."""
    oldest = min(pending, key=lambda item: item[2]) if pending else None
    stale = oldest is not None and _age_hours(oldest[2], now) > PENDING_ALERT_HOURS
    lines = [
        "Automated read-only release-backlog check. It creates no tag, Release,",
        "or dispatch; the tip publisher reconciles every hour on its own.",
        "",
        f"- Pending source releases: {len(pending)}",
    ]
    if oldest is not None:
        lines.append(
            f"- Oldest pending source: `{oldest[1]}` for `{oldest[0]}`, merged "
            f"{oldest[2]} ({_age_hours(oldest[2], now):.1f} h ago)"
        )
    lines.append(
        f"- Last protected-main publisher attempt failed: {'yes' if failed else 'no'}"
    )
    lines.extend(
        [
            "",
            "Read the latest Platform release run: its `RELEASE_DECISION` line",
            "names why the tip is waiting (`ci-red` means main is red), and a",
            "`RELEASE_REFUSED` line names the integrity check that needs the owner.",
        ]
    )
    return (stale or failed), "\n".join(lines) + "\n"


def existing_issue(api: Reader, title: str, label: str) -> dict | None:
    """Exactly one open issue this watchdog itself opened, or none."""
    records = api.get(
        f"/repos/{api.repository}/issues?state=open&labels={label}&per_page=100"
    )
    if not isinstance(records, list):
        raise C.ContractError("issue listing is malformed")
    matches = [
        record
        for record in records
        if isinstance(record, dict)
        and record.get("title") == title
        and "pull_request" not in record
        and isinstance(record.get("user"), dict)
        and record["user"].get("login") == ISSUE_AUTHOR
    ]
    if len(matches) > 1:
        raise C.ContractError("release-backlog issue inventory is ambiguous")
    return matches[0] if matches else None


def announce(api: Reader, *, alerting: bool, body: str, title: str) -> str:
    """One issue, created, refreshed, or closed — never more than one write."""
    current = existing_issue(api, title, ISSUE_LABELS[0])
    if not alerting:
        if current is None:
            return "clear"
        api.write(
            f"/repos/{api.repository}/issues/{current['number']}",
            {"state": "closed"},
            method="PATCH",
        )
        return "closed"
    if current is None:
        api.write(
            f"/repos/{api.repository}/issues",
            {"title": title, "body": body, "labels": list(ISSUE_LABELS)},
            method="POST",
        )
        return "opened"
    api.write(
        f"/repos/{api.repository}/issues/{current['number']}",
        {"body": body},
        method="PATCH",
    )
    return "updated"


def watch(repository: Path, head_sha: str, api: Reader, now: dt.datetime) -> str:
    """Derive the backlog, then publish exactly one issue state for it."""
    boundaries = ledger(repository)
    pending = [
        (boundary.tag, boundary.source_sha,
         C._git(repository, "show", "-s", "--format=%cI", boundary.source_sha))
        for boundary in unreleased(boundaries, api)
    ]
    pending.extend(
        (waiting.tag, waiting.source_sha, waiting.source_date)
        for waiting in plan(repository, head_sha)
    )
    alerting, body = report(tuple(pending), publisher_failed(api), now)
    state = announce(api, alerting=alerting, body=body, title=ISSUE_TITLE)
    return (
        f"Release backlog: {len(pending)} pending source release(s); "
        f"issue {state}.\n\n{body}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "watch"):
        command = commands.add_parser(name)
        command.add_argument("--repository", type=Path, required=True)
        command.add_argument("--head", required=True)
        if name == "watch":
            command.add_argument("--api-repository", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            print(json.dumps([edge.as_dict() for edge in
                              plan(args.repository, args.head)], indent=2))
            return 0
        token = os.environ.get("GITHUB_TOKEN", "")
        api = Reader(token, args.api_repository)
        print(watch(args.repository, args.head, api,
                    dt.datetime.now(dt.timezone.utc)))
        return 0
    except (C.ContractError, KeyError, TypeError, ValueError, OSError) as error:
        print(f"RELEASE_BACKLOG_DENIED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
