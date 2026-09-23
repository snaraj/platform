#!/usr/bin/env python3
"""Read-only admission for the pending source backlog; never a general replayer.

The current protected checkout executes this policy. Historical Git objects are
data, and one canonical first-attempt selection crosses jobs without
reselection. Issue #395 replaced the hand-frozen window with the repository's
own tag ledger: an owner-prepared annotated tag under the immutable tag ruleset
IS the freeze, every fact a table used to transcribe is re-derived from git and
the API here, and one dispatch drains the whole backlog in ledger order.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "recovery_release_backlog", Path(__file__).with_name("release_backlog.py")
)
B = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = B
_spec.loader.exec_module(B)
C = B.C
E = C.EPOCH

SELECTION_SCHEMA = "https://snaraj.dev/schemas/platform-release-recovery-selection/v2"
API = "https://api.github.com/repos/snaraj/platform"
TERMINAL_TREE = "db18c40ece8fa91f9dfabb7cb99a833a34a30505"
TERMINAL_TAG_OBJECT = "e28add890e0af9b0be7c3a8548dad3b6fb7e9324"
TERMINAL_RELEASE_ID = 384446269
TERMINAL_MAIN_RUN = 34186703418
TERMINAL_PUBLISHER_RUN = 34186887764
MAX_JSON = 2 * 1024 * 1024
PUBLISHER_WORKFLOW = "platform-release.yml"
IN_FLIGHT = ("queued", "in_progress", "pending", "requested", "waiting")
EDGE_FIELDS = (
    "tag", "source_sha", "base_tag", "base_sha", "tree_sha", "fragment_path",
    "fragment_sha256", "main_run_id", "main_run_attempt", "codeql_run_id",
    "codeql_run_attempt", "workflows",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise C.ContractError(message)


# Measured over the code path below. EDGE_SECONDS is wall time, taken from
# recovery run 35793384370 (2026-09-22): its prepare step proved nine published
# edges and selected the tenth in 31 s, so 3.5 s an edge, rounded up. One
# headroom figure serves both bounds.
READ_FIXED = 26
READ_PER_EDGE = 9
HEADROOM_PERCENT = 25
DEADLINE_SECONDS = 240
EDGE_SECONDS = 4
# Per-edge publish cost, for the workflow's own `timeout-minutes`. The four
# single-edge dispatches of 2026-09-22/23 (runs 35793384370, 35794132986,
# 35794648655, 35795274166) took 3.5-4.0 min wall each, of which the two
# read-only jobs plus tool install are fixed setup; the publish job's own
# in-loop work — draft, body, sign, two uploads, publish — measured 100-135 s,
# dominated by the ~10 write boundaries, each of which re-walks the ledger.
# Two things moved that figure and both are counted here: `bind` now derives
# the WHOLE v4 ledger rather than one transition window (19.2 s against 15.5 s
# measured warm on the author's laptop, +24 %), and the drain adds one
# independent readback per edge. 135 s x 1.24 + readback rounds to 4.
PUBLISH_FIXED_MINUTES = 6
PUBLISH_EDGE_MINUTES = 4


def per_run_bounds(pending: int) -> tuple[int, int]:
    """Bound one dispatch's reads and seconds from the BACKLOG, not history.

    The reader proves the predecessor, not all of history (issue #395), so its
    cost is FIXED + PER_EDGE x pending and never grows with the number of
    releases already published. The parity argument is the point: the ordinary
    publisher proves exactly one predecessor Release before it publishes, and
    every published edge in between was proved by this same reader, as the
    predecessor, at its own publication. Re-proving them on every later run
    bought nothing and cost an outage at 47 edges (issue #393).

    * PER_EDGE = 9 — one Release probe for the newest-first scan that finds the
      edge, its owner-prepared tag (ref + tag object) 2, the two original run
      listings 2, and `prove_ci` 4 (a run attempt and a job page for main and
      for CodeQL).
    * FIXED = 26 — `prove_context` 3 (repository, protected ref, this run), the
      publisher-in-flight probe 1, the scan's own stop probe on the predecessor
      1, the two executor run listings 2, `prove_ci` for the executor 4, the
      terminal v3 checkpoint 7 (its ref, Release, tag object, both identity
      assets and the two runs its identity names), and the predecessor Release
      8 (those seven plus the v4 executor main-CI run).

    HEADROOM_PERCENT keeps the bound from tracking the measurement so exactly
    that one added read anywhere reintroduces the same outage; the result is
    still a hard cap, enforced on every read. The seconds bound is derived from
    the same walk: 240 s covers 47 edges at the measured cost, and a backlog
    that outgrows it refuses here rather than part-way through a publication.
    """
    require(type(pending) is int and pending > 0, "per-run bounds need a nonempty backlog")
    reads = READ_FIXED + READ_PER_EDGE * pending
    reads += -(-reads * HEADROOM_PERCENT // 100)
    # A run proves the terminal checkpoint and the predecessor beside the backlog.
    seconds = EDGE_SECONDS * (pending + 2)
    require(DEADLINE_SECONDS * 100 >= seconds * (100 + HEADROOM_PERCENT),
            "pending backlog cannot be walked inside the recovery deadline")
    return reads, DEADLINE_SECONDS


def max_pending_edges() -> int:
    """The longest backlog one dispatch can admit, derived from the deadline.

    `per_run_bounds` refuses a backlog its own seconds budget could not walk,
    so the answer is not chosen: it is the largest length that budget accepts,
    and the publish job's `timeout-minutes` is derived from it below rather
    than guessed. Extending either constant re-derives both.
    """
    pending = 1
    while pending < C.MAX_TAG_LEDGER_ENTRIES:
        try:
            per_run_bounds(pending + 1)
        except C.ContractError:
            return pending
        pending += 1
    return pending


def publish_timeout_minutes() -> int:
    """The publish job's wall budget for draining a maximum-length backlog.

    Fixed setup plus the measured in-loop per-edge cost, for as many edges as
    `prepare` can admit, carrying the same HEADROOM_PERCENT every other derived
    bound here carries — a timeout sitting exactly on its measurement turns one
    slow runner into a mid-edge kill. It is a hard cap in the same sense the
    read budget is: a drain that outgrows it is stopped by GitHub, mid-edge at
    worst, and the per-edge write boundaries keep that from leaving anything
    but a draft the owner deletes.
    """
    minutes = PUBLISH_FIXED_MINUTES + PUBLISH_EDGE_MINUTES * max_pending_edges()
    return -(-minutes * (100 + HEADROOM_PERCENT) // 100)


def canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _widest_edge() -> dict[str, object]:
    """One edge record at its maximum canonical width, for the byte bound."""
    return {
        "tag": "v" + "9" * 20, "source_sha": "0" * 40, "base_tag": "v" + "9" * 20,
        "base_sha": "0" * 40, "tree_sha": "0" * 40,
        "fragment_path": "changelog.d/" + "9" * 8 + "-" + "a" * 64 + ".md",
        "fragment_sha256": "0" * 64, "main_run_id": 9 * 10 ** 18,
        "main_run_attempt": 9 * 10 ** 3, "codeql_run_id": 9 * 10 ** 18,
        "codeql_run_attempt": 9 * 10 ** 3,
        "workflows": {path: "0" * 64 for path in B.WORKFLOW_AUDIT_PATHS},
    }


def selection_bytes(pending: int) -> int:
    """The byte budget for a selection carrying `pending` edges.

    Derived by rendering the envelope and one maximum-width edge rather than
    chosen: a literal budget silently stops fitting at some backlog length, and
    that backlog is the one nobody can drain (the same failure shape as the
    read cap in issue #393).
    """
    require(type(pending) is int and pending > 0, "selection bytes need a nonempty backlog")
    envelope = {"schema": SELECTION_SCHEMA, "repository": E.NEW_REPOSITORY,
                "repository_id": E.REPOSITORY_ID, "executor_sha": "0" * 40,
                "run_id": 9 * 10 ** 18, "run_attempt": 9 * 10 ** 3,
                "executor_main_run_id": 9 * 10 ** 18, "executor_main_run_attempt": 9 * 10 ** 3,
                "executor_codeql_run_id": 9 * 10 ** 18, "executor_codeql_run_attempt": 9 * 10 ** 3,
                "edges": []}
    fixed = len(canonical(envelope).encode())
    per_edge = len(canonical(_widest_edge()).encode()) + 1
    return fixed + per_edge * pending


def positive(value: object) -> int:
    require(type(value) is int and value > 0, "run identity is not a positive integer")
    return value


def context(environment: dict, event: dict) -> dict:
    """Only a first attempt of the no-input protected-main workflow can select."""
    require(environment.get("GITHUB_API_URL") == "https://api.github.com", "foreign API")
    require(environment.get("GITHUB_REPOSITORY") == E.NEW_REPOSITORY, "foreign repository")
    require(environment.get("GITHUB_REPOSITORY_ID") == str(E.REPOSITORY_ID), "foreign repository object")
    require(environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "recovery needs a dispatch")
    require(environment.get("GITHUB_REF") == C.PROTECTED_REF, "recovery needs protected main")
    require(environment.get("GITHUB_RUN_ATTEMPT") == "1", "recovery reruns refuse; use a fresh no-input dispatch")
    expected = f"{E.NEW_REPOSITORY}/{E.RECOVERY_WORKFLOW}@{C.PROTECTED_REF}"
    require(environment.get("GITHUB_WORKFLOW_REF") == expected, "foreign recovery workflow")
    sha = C.require_sha(environment.get("GITHUB_SHA"), "executor SHA")
    require(environment.get("GITHUB_WORKFLOW_SHA") == sha, "executor and workflow SHA differ")
    run = environment.get("GITHUB_RUN_ID", "")
    require(isinstance(run, str) and re.fullmatch(r"[1-9][0-9]*", run) is not None, "foreign run ID")
    repository = event.get("repository", {})
    require(isinstance(repository, dict), "event repository missing")
    E.repository(repository.get("full_name"), repository.get("id"))
    require(repository.get("full_name") == E.NEW_REPOSITORY and repository.get("default_branch") == "main",
            "event repository or default branch differs")
    require(event.get("inputs") in (None, {}), "recovery accepts no inputs")
    return {"repository": E.NEW_REPOSITORY, "repository_id": E.REPOSITORY_ID,
            "executor_sha": sha, "run_id": int(run), "run_attempt": 1}


def prove_trees(root: Path, bound: dict) -> None:
    """The checkout is the executor, and the terminal checkpoint tree is exact.

    The membership refusal that used to live here is gone with the table it
    read: a published edge's own executor later becomes a frozen source as the
    backlog drains behind main, which is the ordinary case rather than a
    replay. `EPOCH.validate_execution` now decides that by the executor
    RELATION, proved per identity against this same checkout.
    """
    require(C._git(root, "rev-parse", "HEAD") == bound["executor_sha"], "checkout differs from executor")
    require(C._git(root, "rev-parse", f"{E.TERMINAL_V3_SOURCE}^{{tree}}") == TERMINAL_TREE,
            "terminal tree differs")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicAPI:
    """Bounded GETs only; asset redirects never receive the API credential.

    The read bound follows the BACKLOG this run must drain. It starts at the
    bound for one pending edge and is widened, one edge at a time, only while
    the newest-first scan proves another edge is actually pending — and never
    past the number of v4 tags the checkout itself holds, so a hostile API
    cannot lengthen the walk. Lowering it is not possible.
    """

    def __init__(self, token: str | None, *, pending: int = 1):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)
        self.started = time.monotonic()
        self.max_reads, self.max_seconds = per_run_bounds(pending)
        self.deadline = self.started + self.max_seconds
        self.requests = 0

    def widen(self, pending: int) -> None:
        reads, _seconds = per_run_bounds(pending)
        require(reads >= self.max_reads, "a read bound can only widen with the backlog")
        self.max_reads = reads

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def read(self, path: str, *, limit: int = MAX_JSON, asset: bool = False) -> tuple[int, bytes]:
        require(isinstance(path, str) and (path == "" or path.startswith("/")) and
                not any(value in path for value in ("..", "#", "\\", "\r", "\n")), "foreign API path")
        self.requests += 1
        remaining = self.deadline - time.monotonic()
        require(self.requests <= self.max_reads and remaining > 0,
                f"recovery read budget exhausted at read {self.requests}/{self.max_reads} "
                f"after {self.elapsed:.1f}s/{self.max_seconds}s")
        headers = {"Accept": "application/octet-stream" if asset else "application/vnd.github+json",
                   "X-GitHub-Api-Version": C.GITHUB_API_VERSION}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(API + path, headers=headers, method="GET")
        try:
            response = self.opener.open(request, timeout=min(20, remaining))
        except urllib.error.HTTPError as error:
            with error:
                if asset and error.code == 302:
                    location = error.headers.get("Location", "")
                    target = urllib.parse.urlsplit(location)
                    require(target.scheme == "https" and target.hostname == "release-assets.githubusercontent.com"
                            and target.port in (None, 443) and not target.username and not target.password
                            and not target.fragment, "foreign asset redirect")
                    # A new request with no Authorization; a second redirect refuses.
                    response = self.opener.open(urllib.request.Request(location, method="GET"),
                                                timeout=min(20, remaining))
                elif error.code == 404 and not asset:
                    return 404, b""
                else:
                    raise C.ContractError(f"GitHub read refused with HTTP {error.code} for {path}") from error
        with response:
            require(response.status == 200, f"GitHub read did not return 200 for {path}")
            value = response.read(limit + 1)
            require(len(value) <= limit, f"GitHub response exceeds its byte budget for {path}")
            return 200, value

    def get(self, path: str, *, absent: bool = False) -> dict | None:
        status, data = self.read(path)
        if status == 404:
            require(absent, f"required GitHub record missing at {path}; delivery remains held")
            return None
        value = json.loads(data)
        require(isinstance(value, dict), "GitHub object response required")
        return value


def exact_run(api: PublicAPI, run_id: int, attempt: int) -> dict:
    positive(run_id)
    positive(attempt)
    value = api.get(f"/actions/runs/{run_id}/attempts/{attempt}")
    require((value.get("id"), value.get("run_attempt")) == (run_id, attempt), "run attempt substitution")
    for field in ("repository", "head_repository"):
        repository = value.get(field, {})
        require(isinstance(repository, dict), "run repository absent")
        E.repository(repository.get("full_name"), repository.get("id"))
        require(repository.get("full_name") == E.NEW_REPOSITORY, "run repository name differs")
    return value


def run_tuple(api: PublicAPI, source: str, workflow: str) -> tuple[int, int]:
    """The ONE protected-main push run of a workflow at one source, latest attempt.

    This is the attempt the ordinary publisher would itself have consumed:
    `workflow_run` fires on the completed attempt, and the listing reports each
    run's latest attempt. Replacing the old attempt-1 literal with the same
    rule the ordinary path uses is parity rather than a relaxation — `prove_ci`
    still requires that exact attempt's required-jobs receipt.
    """
    value = api.get(f"/actions/workflows/{workflow}/runs?branch=main&event=push&head_sha={source}&per_page=100")
    require(set(value) == {"total_count", "workflow_runs"} and type(value["total_count"]) is int
            and value["total_count"] == 1 and len(value["workflow_runs"]) == 1,
            f"{workflow} needs exactly one complete main workflow listing at {source}")
    run = value["workflow_runs"][0]
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            f"{workflow} latest attempt at {source} did not conclude success")
    return positive(run.get("id")), positive(run.get("run_attempt"))


def prove_ci(api: PublicAPI, source: str, tree: str, main: tuple[int, int], codeql: tuple[int, int]) -> None:
    main_record = exact_run(api, *main)
    require(C.plan_workflow_run({"repository": main_record["repository"], "workflow_run": main_record},
                               E.NEW_REPOSITORY) == source, "main run source differs")
    require(main_record.get("head_commit", {}).get("id") == source and
            main_record.get("head_commit", {}).get("tree_id") == tree, "main run tree differs")
    codeql_record = exact_run(api, *codeql)
    codeql_runs = {"total_count": 1, "workflow_runs": [codeql_record]}
    require(C.classify_codeql_run(codeql_runs, source) == codeql, "CodeQL is not the exact successful attempt")
    main_jobs = api.get(f"/actions/runs/{main[0]}/attempts/{main[1]}/jobs?per_page=100")
    codeql_jobs = api.get(f"/actions/runs/{codeql[0]}/attempts/{codeql[1]}/jobs?per_page=100")
    C.build_main_ci_jobs_receipt(main_jobs, codeql_runs, codeql_jobs, E.NEW_REPOSITORY,
                                str(main[0]), str(main[1]), source)


def prove_context(root: Path, api: PublicAPI, bound: dict) -> None:
    prove_trees(root, bound)
    repository = api.get("")
    E.repository(repository.get("full_name"), repository.get("id"))
    require(repository.get("full_name") == E.NEW_REPOSITORY and repository.get("default_branch") == "main",
            "current repository identity or default branch differs")
    ref = api.get("/git/ref/heads/main")
    require(ref.get("ref") == C.PROTECTED_REF and ref.get("object", {}).get("type") == "commit"
            and ref.get("object", {}).get("sha") == bound["executor_sha"], "executor is no longer current protected main")
    run = exact_run(api, bound["run_id"], bound["run_attempt"])
    require(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("head_sha") == bound["executor_sha"] and run.get("path") == E.RECOVERY_WORKFLOW
            and run.get("status") == "in_progress" and run.get("conclusion") is None,
            "current recovery execution record differs")
    require(run.get("head_commit", {}).get("id") == bound["executor_sha"] and
            run.get("head_commit", {}).get("tree_id") == C._git(root, "rev-parse", "HEAD^{tree}"),
            "current recovery execution tree differs")


def prove_no_publisher_in_flight(api: PublicAPI) -> None:
    """Refuse while the ordinary publisher holds a protected-main transaction.

    A drain and the tip merge's own publisher would otherwise race for the same
    next patch: the publisher waits for its predecessor Release, the drain
    publishes it, and both then believe they own the edge after it. One bounded
    listing closes that by construction.
    """
    value = api.get(f"/actions/workflows/{PUBLISHER_WORKFLOW}/runs?branch=main&per_page=1")
    require(set(value) == {"total_count", "workflow_runs"} and isinstance(value["workflow_runs"], list),
            "publisher run listing is malformed")
    for record in value["workflow_runs"]:
        require(isinstance(record, dict), "publisher run record is malformed")
        require(record.get("status") not in IN_FLIGHT,
                "ordinary platform-release publisher is queued or in progress; "
                "let it finish before draining the backlog")


def verify_signature(identity: bytes, bundle: bytes, tag: str) -> None:
    value = json.loads(identity)
    args = []
    selected = E.identity(tag)
    if selected["version"] == 4:
        selected = E.identity(tag, recovering=E.recovering_identity(value))
        args = ["--certificate-github-workflow-sha", value["execution"]["source_sha"],
                "--certificate-github-workflow-trigger", selected["publisher_event"]]
    with tempfile.TemporaryDirectory(prefix="platform-recovery-identity-") as scratch:
        path = Path(scratch)
        (path / "identity.json").write_bytes(identity)
        (path / "bundle.json").write_bytes(bundle)
        environment = dict(os.environ)
        environment.pop("COSIGN_REPOSITORY", None)
        subprocess.run(["cosign", "verify-blob", "--timeout", "30s", "--bundle", str(path / "bundle.json"),
                        "--certificate-identity", selected["subject"], "--certificate-oidc-issuer",
                        C.SELECTOR_CERTIFICATE_ISSUER, *args, str(path / "identity.json")],
                       check=True, timeout=40, stdout=subprocess.DEVNULL, env=environment)


def prove_tag(root: Path, api: PublicAPI, tag: str, source: str, ref: dict | None) -> str:
    """A dangling object cannot substitute for the owner's exact prepared ref."""
    require(ref is not None, f"owner-prepared annotated tag {tag} missing; recovery remains held")
    object_sha = C.require_sha(ref.get("object", {}).get("sha"), "tag object")
    annotated = api.get(f"/git/tags/{object_sha}")
    C.validate_tag_record(ref, annotated, tag=tag, source_sha=source,
                          message=f"Platform release {tag} from {source}",
                          tagger_name=C.RELEASE_TAGGER_NAME, tagger_email=C.RELEASE_TAGGER_EMAIL,
                          tagger_date=C._git(root, "show", "-s", "--format=%cI", source))
    require(C._git(root, "rev-parse", f"refs/tags/{tag}") == object_sha, "fetched and API tag objects differ")
    return object_sha


def release_present(api: PublicAPI, tag: str) -> bool:
    """One bounded probe: does this tag carry a published (non-draft) Release?"""
    record = api.get(f"/releases/tags/{tag}", absent=True)
    if record is None:
        return False
    require(record.get("draft") is False,
            f"{tag} carries a draft Release; the owner deletes a partial draft")
    return True


def prove_release(root: Path, api: PublicAPI, tag: str, source: str) -> bool:
    """Only an exact immutable release with its ORIGINAL completed run advances."""
    ref = api.get(f"/git/ref/tags/{tag}", absent=True)
    release = api.get(f"/releases/tags/{tag}", absent=True)
    if ref is None:
        require(release is None, "Release without its exact annotated tag")
        return False
    object_sha = prove_tag(root, api, tag, source, ref)
    if release is None:
        return False
    selected = E.identity(tag)
    assets = release.get("assets", [])
    require(isinstance(assets, list) and len(assets) == 2,
            f"partial or foreign release remains held for {tag}")
    require(all(isinstance(asset, dict) for asset in assets) and
            {asset.get("name", "") for asset in assets} == {selected["asset"], selected["bundle"]},
            f"foreign identity asset names remain held for {tag}")
    raw = {}
    for asset in assets:
        asset_id = positive(asset.get("id"))
        limit = C.MAX_RELEASE_IDENTITY_BYTES if asset["name"] == selected["asset"] else C.MAX_RELEASE_IDENTITY_BUNDLE_BYTES
        require(type(asset.get("size")) is int and 0 < asset["size"] <= limit, "identity asset size exceeds budget")
        status, data = api.read(f"/releases/assets/{asset_id}", limit=limit, asset=True)
        require(status == 200, "identity asset download failed")
        raw[asset["name"]] = data
    identity, bundle = raw[selected["asset"]], raw[selected["bundle"]]
    descends = C._identity_executor_descends(root, C._canonical_release_identity(identity))
    C.validate_identity_release_record(release, identity=identity, bundle=bundle, tag=tag, source_sha=source,
                                      tag_object_sha=object_sha, tree_sha=C._git(root, "rev-parse", f"{source}^{{tree}}"),
                                      api_repository=E.NEW_REPOSITORY, api_repository_id=E.REPOSITORY_ID,
                                      executor_descends=descends)
    verify_signature(identity, bundle, tag)
    value = json.loads(identity)
    if selected["version"] == 4:
        # The ledger, not a transcribed row, binds what this identity claims
        # about its own edge. The retired table pinned the fragment path, its
        # SHA-256 and the predecessor for exactly thirteen edges; this derives
        # them for every edge, from the tag the owner pushed.
        window = C.discover_transition_window(root, source)
        require(value.get("changelog") == {"fragment_path": window.fragment_path,
                                           "fragment_sha256": "sha256:" + window.fragment_sha256},
                f"published {tag} names a fragment the ledger does not derive")
        require(value.get("predecessor") == {"tag": window.base_tag, "peeled_commit": window.base_sha},
                f"published {tag} names a predecessor the ledger does not derive")
        require(window.intent.tag == tag, f"published {tag} is not the ledger edge at its source")
    if tag == E.TERMINAL_V3_TAG:
        require((object_sha, release["id"], value["main_ci"]["run_id"], value["main_ci"]["run_attempt"],
                 value["platform_release"]["run_id"], value["platform_release"]["run_attempt"]) ==
                (TERMINAL_TAG_OBJECT, TERMINAL_RELEASE_ID, TERMINAL_MAIN_RUN, 1, TERMINAL_PUBLISHER_RUN, 1),
                "terminal v3 identity differs from the frozen checkpoint")
    runs = [exact_run(api, value[name]["run_id"], value[name]["run_attempt"])
            for name in ("main_ci", "platform_release")]
    executor = None
    if selected["version"] == 4 and E.recovering_identity(value):
        ci = value["execution"]["main_ci"]
        executor = exact_run(api, ci["run_id"], ci["run_attempt"])
    # Pending, failed, cancelled, missing or unknown original publisher refuses.
    # An immutable payload naming a failed attempt has no settlement path here.
    if selected["version"] == 4 and runs[1].get("status") in set(IN_FLIGHT):
        C.validate_identity_run_records(identity, *runs, execution_main_run_record=executor,
                                        platform_pending=True, executor_descends=descends)
        raise C.PendingRelease(f"original publisher attempt for {tag} is still pending; do not advance")
    C.validate_identity_run_records(identity, *runs, execution_main_run_record=executor,
                                    executor_descends=descends)
    return True


def edge_record(edge, main: tuple[int, int], codeql: tuple[int, int]) -> dict:
    """One selection entry: the git-derived edge plus its original run tuple."""
    return {"tag": edge.tag, "source_sha": edge.source_sha, "base_tag": edge.base_tag,
            "base_sha": edge.base_sha, "tree_sha": edge.tree_sha,
            "fragment_path": edge.fragment_path, "fragment_sha256": edge.fragment_sha256,
            "main_run_id": main[0], "main_run_attempt": main[1],
            "codeql_run_id": codeql[0], "codeql_run_attempt": codeql[1],
            "workflows": dict(edge.workflows)}


def binding(root: Path, bound: dict, supplied: str, *, ledger=None) -> dict:
    """Recheck the fixed receipt locally without changing its selected edges."""
    require(len(supplied.encode()) <= selection_bytes(C.MAX_TAG_LEDGER_ENTRIES),
            "selection exceeds its byte budget")
    value = json.loads(supplied)
    require(isinstance(value, dict) and canonical(value) == supplied, "selection must be canonical JSON")
    fields = {"schema", *bound, "edges", "executor_main_run_id", "executor_main_run_attempt",
              "executor_codeql_run_id", "executor_codeql_run_attempt"}
    require(set(value) == fields and value["schema"] == SELECTION_SCHEMA, "foreign selection fields")
    require(all(value[key] == expected and type(value[key]) is type(expected) for key, expected in bound.items()),
            "selection belongs to another executor, run or attempt")
    edges = value["edges"]
    require(isinstance(edges, list) and edges, "selection carries no pending edge")
    require(len(supplied.encode()) <= selection_bytes(len(edges)),
            "selection exceeds the byte budget its own length derives")
    for key in ("executor_main_run_id", "executor_main_run_attempt",
                "executor_codeql_run_id", "executor_codeql_run_attempt"):
        positive(value[key])
    # ONE ledger walk decides what every entry is. The list never gets to say:
    # a reordered, dropped, duplicated or re-chained entry disagrees with the
    # repository's own tags here, and an entry outside the ledger has no edge.
    ledger = {edge.tag: edge for edge in
              (B.published_edges(root, after=E.TERMINAL_V3_TAG) if ledger is None else ledger)}
    previous = None
    seen = set()
    for entry in edges:
        require(isinstance(entry, dict) and set(entry) == set(EDGE_FIELDS), "foreign selection edge fields")
        require(entry["tag"] not in seen, "selection repeats an edge")
        seen.add(entry["tag"])
        for key in ("main_run_id", "main_run_attempt", "codeql_run_id", "codeql_run_attempt"):
            positive(entry[key])
        derived = ledger.get(entry["tag"])
        require(derived is not None, f"selected edge {entry['tag']} is outside the derived ledger")
        require(edge_record(derived, (entry["main_run_id"], entry["main_run_attempt"]),
                            (entry["codeql_run_id"], entry["codeql_run_attempt"])) == entry,
                f"selected edge {entry['tag']} no longer matches the repository")
        require(previous is None or (entry["base_tag"], entry["base_sha"]) ==
                (previous["tag"], previous["source_sha"]),
                "selected edge does not chain to its predecessor entry")
        E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, entry["tag"], entry["base_tag"],
                      entry["base_sha"], entry["source_sha"], recovering=True)
        previous = entry
    return value


def selection(root: Path, api: PublicAPI, bound: dict, supplied: str | None = None,
              stream=sys.stdout) -> dict:
    prove_context(root, api, bound)
    prove_no_publisher_in_flight(api)
    ledger = B.published_edges(root, after=E.TERMINAL_V3_TAG)
    require(ledger, "no v4 tag exists; there is nothing to drain")
    if supplied is None:
        # Newest-first until the first published Release: those after it are the
        # backlog. The cap widens one edge at a time and never past the tags the
        # checkout itself holds, so the walk is bounded by git, not by the API.
        pending: list = []
        predecessor = None
        for edge in reversed(ledger):
            if pending:
                api.widen(min(len(pending), len(ledger)))
            if release_present(api, edge.tag):
                predecessor = edge
                break
            pending.append(edge)
        pending.reverse()
        require(pending, "the source backlog is complete; use the ordinary publisher")
    else:
        value = binding(root, bound, supplied, ledger=ledger)
        api.widen(len(value["edges"]))
        tags = {edge.tag: edge for edge in ledger}
        pending = []
        for entry in value["edges"]:
            require(entry["tag"] in tags, "selected edge is outside the derived ledger")
            pending.append(tags[entry["tag"]])
        first = pending[0]
        predecessor = next((edge for edge in ledger if edge.tag == first.base_tag), None)
        require(first.base_tag == E.TERMINAL_V3_TAG or predecessor is not None,
                "selected predecessor is outside the derived ledger")
    require(prove_release(root, api, E.TERMINAL_V3_TAG, E.TERMINAL_V3_SOURCE), "terminal v3 Release missing")
    if predecessor is not None and predecessor.tag != E.TERMINAL_V3_TAG:
        require(prove_release(root, api, predecessor.tag, predecessor.source_sha),
                f"predecessor Release {predecessor.tag} remains incomplete")
    if supplied is None:
        main = run_tuple(api, bound["executor_sha"], "pull-request.yml")
        codeql = run_tuple(api, bound["executor_sha"], "codeql.yml")
    else:
        main = (value["executor_main_run_id"], value["executor_main_run_attempt"])
        codeql = (value["executor_codeql_run_id"], value["executor_codeql_run_attempt"])
    prove_ci(api, bound["executor_sha"], C._git(root, "rev-parse", f"{bound['executor_sha']}^{{tree}}"), main, codeql)
    records = []
    for edge in pending:
        before = api.requests
        started = api.elapsed
        # Admission precedes settings-token acquisition and is repeated by publish.
        prove_tag(root, api, edge.tag, edge.source_sha,
                  api.get(f"/git/ref/tags/{edge.tag}", absent=True))
        original_main = run_tuple(api, edge.source_sha, "pull-request.yml")
        original_codeql = run_tuple(api, edge.source_sha, "codeql.yml")
        prove_ci(api, edge.source_sha, edge.tree_sha, original_main, original_codeql)
        records.append(edge_record(edge, original_main, original_codeql))
        print(f"RECOVERY_EDGE tag={edge.tag} source={edge.source_sha} "
              f"reads={api.requests - before} seconds={api.elapsed - started:.1f} "
              f"decision=selected workflows="
              + ",".join(f"{path.rsplit('/', 1)[1]}:{digest[:12]}" for path, digest in edge.workflows),
              file=stream)
    if supplied is None:
        value = {"schema": SELECTION_SCHEMA, **bound, "edges": records,
                 "executor_main_run_id": main[0], "executor_main_run_attempt": main[1],
                 "executor_codeql_run_id": codeql[0], "executor_codeql_run_attempt": codeql[1]}
    else:
        # `verify` re-derives every edge from git and the API and compares it
        # with the receipt the first attempt fixed. A receipt that no longer
        # re-derives is refused; it is never quietly replaced.
        require(records == value["edges"],
                "re-derived edges differ from the receipt this run is bound to")
    print(f"RECOVERY_SUMMARY pending={len(records)} published=0 "
          f"reads={api.requests}/{api.max_reads} "
          f"seconds={api.elapsed:.1f}/{api.max_seconds}", file=stream)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "bind", "readback", "predecessor"))
    args = parser.parse_args(argv)
    # The credential is never inherited by Git, cosign or other child processes.
    token = os.environ.pop("RECOVERY_READ_TOKEN", None)
    try:
        require(not any(os.environ.get(name) for name in
                        ("GH_TOKEN", "GITHUB_TOKEN", "IMMUTABLE_SETTINGS_TOKEN", "ACTIONS_READ_TOKEN",
                         "CONTENTS_READ_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")), "ambient credential refused")
        if args.command == "predecessor":
            require(os.environ.get("GITHUB_API_URL") == "https://api.github.com", "foreign API")
            E.repository(os.environ["GITHUB_REPOSITORY"], int(os.environ["GITHUB_REPOSITORY_ID"]))
            require(os.environ["GITHUB_REPOSITORY"] == E.NEW_REPOSITORY, "foreign repository")
            window = C.discover_transition_window(Path.cwd(), os.environ["SOURCE_SHA"])
            require(prove_release(Path.cwd(), PublicAPI(token), window.base_tag, window.base_sha), "predecessor Release absent")
            print("PREDECESSOR=PASS")
            return 0
        with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as source:
            raw_event = source.read(MAX_JSON + 1)
        require(len(raw_event) <= MAX_JSON, "event exceeds its byte budget")
        bound = context(dict(os.environ), json.loads(raw_event))
        supplied = os.environ.get("RECOVERY_SELECTION")
        require((args.command in {"verify", "bind", "readback"}) == (supplied is not None),
                "selection mode differs")
        if args.command == "readback":
            # The drain's own independent proof that the edge it just published
            # is a complete immutable Release: two assets, canonical identity,
            # Sigstore subject, executor record and both original attempts.
            prove_trees(Path.cwd(), bound)
            value = binding(Path.cwd(), bound, supplied)
            selected = os.environ.get("RECOVERY_EDGE_TAG")
            matches = [entry for entry in value["edges"] if entry["tag"] == selected]
            require(len(matches) == 1, "readback names no single published edge")
            entry = matches[0]
            api = PublicAPI(token)
            require(prove_release(Path.cwd(), api, entry["tag"], entry["source_sha"]),
                    f"published Release {entry['tag']} did not read back complete")
            print(f"RECOVERY_READBACK=PASS tag={entry['tag']} reads={api.requests} "
                  f"seconds={api.elapsed:.1f}")
            return 0
        if args.command == "bind":
            prove_trees(Path.cwd(), bound)
            value = binding(Path.cwd(), bound, supplied)
            selected = os.environ.get("RECOVERY_EDGE_TAG")
            matches = [entry for entry in value["edges"] if entry["tag"] == selected]
            require(len(matches) == 1, "publisher names no single selected edge")
            entry = matches[0]
            for field in ("source_sha", "tag", "base_sha", "base_tag"):
                require(os.environ.get(field.upper()) == entry[field], "publisher differs from selected edge")
            require(os.environ.get("MAIN_RUN_ID") == str(entry["main_run_id"])
                    and os.environ.get("MAIN_RUN_ATTEMPT") == str(entry["main_run_attempt"]),
                    "publisher original CI differs")
            require(os.environ.get("EXECUTION_MAIN_RUN_ID") == str(value["executor_main_run_id"])
                    and os.environ.get("EXECUTION_MAIN_RUN_ATTEMPT") == str(value["executor_main_run_attempt"]),
                    "publisher executor CI differs")
            print(f"RECOVERY_BINDING=PASS tag={entry['tag']}")
            return 0
        pending_hint = 1
        if supplied is not None:
            require(len(supplied.encode()) <= selection_bytes(C.MAX_TAG_LEDGER_ENTRIES),
                    "selection exceeds its byte budget")
            parsed = json.loads(supplied)
            require(isinstance(parsed, dict) and isinstance(parsed.get("edges"), list) and parsed["edges"],
                    "selection carries no pending edge")
            pending_hint = len(parsed["edges"])
        value = selection(Path.cwd(), PublicAPI(token, pending=pending_hint), bound, supplied)
        encoded = canonical(value)
        require(len(encoded.encode()) <= selection_bytes(len(value["edges"])),
                "selection exceeds its byte budget")
        if args.command == "prepare":
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                output.write(f"selection={encoded}\npending={len(value['edges'])}\n"
                             f"source_sha={value['edges'][0]['source_sha']}\n")
        print(f"RECOVERY_SELECTION=PASS pending={len(value['edges'])} "
              f"tags={','.join(entry['tag'] for entry in value['edges'])} "
              f"executor={value['executor_sha']} run={value['run_id']}:1")
        return 0
    except C.PendingRelease as error:
        print(f"recovery pending: {error}", file=sys.stderr)
        return 3
    except (C.ContractError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"recovery refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
