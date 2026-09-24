#!/usr/bin/env python3
"""Tip-only platform source publication (issue #397).

A run publishes only the current protected-main tip: the commit whose workflow
and scripts are executing, after that commit's main CI and CodeQL succeeded.
The Release binds every changelog fragment added since the previous Release,
so a merge that lands while an earlier merge is still in CI never strands a
backlog; the newest green tip carries both. The executor is the source by
construction, and no owner action is part of the routine path.

Three entry points run in three jobs of ``platform-release.yml``:

* ``admit`` (read-only token) decides ``publish``, ``finalize`` or a named
  no-op. It proves the tip, its CI and CodeQL, and the latest Release.
* ``stage`` is the evidence job (``contents: write`` + OIDC). Everything it
  writes is private and disposable: a content-addressed tag object without a
  ref, and a draft Release carrying both signed assets. The v5 identity names
  this job, and its success is the finalization proof verifiers require.
* ``publish`` (``contents: write`` only) creates the tag ref, which is the
  commit point, and flips the draft to an immutable Release. It also finalizes
  an earlier committed Release whose staged evidence verifies.

Before the commit point a failed transaction is discarded; after it the
transaction only rolls forward. Every decision prints one ``RELEASE_DECISION``
line and every refused API call prints its HTTP status and a bounded body
slice, so no failure is mute.
"""

from __future__ import annotations

import argparse
import hashlib
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
from typing import Callable

_spec = importlib.util.spec_from_file_location(
    "tip_release_contract", Path(__file__).with_name("platform_release_contract.py")
)
C = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = C
_spec.loader.exec_module(C)
E = C.EPOCH

API_ROOT = "https://api.github.com"
API_REPOSITORY = f"/repos/{E.NEW_REPOSITORY}"
UPLOAD_PREFIX = f"https://uploads.github.com/repos/{E.NEW_REPOSITORY}/releases/"
# GitHub serves asset bytes from a signed redirect; the API credential never
# follows it. Both hosts GitHub documents for release assets are accepted.
ASSET_HOSTS = frozenset({"release-assets.githubusercontent.com", "objects.githubusercontent.com"})
PLAN_SCHEMA = "https://snaraj.dev/schemas/platform-release-tip-plan/v1"
WORKFLOW_NAME = "Platform release"
BOT = {"login": "github-actions[bot]", "id": 41898282}
IN_FLIGHT = frozenset({"queued", "in_progress", "pending", "requested", "waiting"})
MAX_JSON_BYTES = 2 * 1024 * 1024
BODY_SLICE_BYTES = 512
# GitHub rejects a Release body above 125,000 characters; past this budget the
# notes list every fragment by path and digest and leave the texts to the tag.
NOTES_BUDGET_BYTES = 100_000
# A committed-but-unflipped Release or a failed stage can leave at most one
# draft per attempt; more than this is not a routine leftover and refuses.
MAX_DISCARDS = 3
RELEASE_PAGES = -(-C.MAX_TAG_LEDGER_ENTRIES // 100)
# CodeQL runs beside main CI and usually finishes within minutes of it. Admit
# waits this long before leaving the tip to the hourly reconciliation.
CODEQL_POLLS = 30
CODEQL_POLL_SECONDS = 10
READBACK_POLLS = 5

# Request budgets, counted over the longest path of each entry point (a test
# replays that path against the fake transport and asserts the count). The
# headroom keeps one added read from turning into an outage, as in issue #393.
CONTEXT_READS = 1  # the protected main ref
CI_READS = 2  # the exact-SHA main run listing and its attempt's jobs
CODEQL_READS = 2  # the exact-SHA CodeQL listing and its attempt's jobs, per poll
PROOF_READS = 8  # ref, tag object, Release, two assets, two runs, evidence jobs
REDIRECT_READS = 2  # each asset download may follow one signed redirect
HEADROOM_PERCENT = 25


def _with_headroom(reads: int) -> int:
    return reads + -(-reads * HEADROOM_PERCENT // 100)


ADMIT_BUDGET = _with_headroom(
    CONTEXT_READS + CI_READS + CODEQL_READS * CODEQL_POLLS + 1 + PROOF_READS + REDIRECT_READS
)
# stage: tip, latest proof, tag probe, release pages, discards (DELETE + GET),
# tag object POST + GET, draft POST, two uploads, staged GET, two downloads.
STAGE_BUDGET = _with_headroom(
    CONTEXT_READS + 1 + PROOF_READS + REDIRECT_READS + 1 + RELEASE_PAGES
    + 2 * MAX_DISCARDS + 2 + 1 + 2 + 1 + 2 + REDIRECT_READS
)
# publish: release pages (finalize), staged proof, tag probe, ref POST +
# readback, flip + readbacks, published proof.
PUBLISH_BUDGET = _with_headroom(
    RELEASE_PAGES + PROOF_READS + REDIRECT_READS + 1 + 2 + 1 + READBACK_POLLS
    + PROOF_READS + REDIRECT_READS
)
DEADLINE_SECONDS = 600

Transport = Callable[[str, str, dict, "bytes | None", float], "tuple[int, dict, bytes]"]


class Refusal(C.ContractError):
    """A named refusal. The run fails, and the watchdog reports it."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def log(line: str, *, summary: bool = True) -> None:
    """One line to the job log; decisions also go to the job summary."""
    print(line, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n\n")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None,
                     timeout: float) -> tuple[int, dict, bytes]:
    """The production network boundary; tests replace exactly this function."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(MAX_JSON_BYTES + 1)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, dict(error.headers or {}), error.read(MAX_JSON_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise Refusal(f"network failure on {method} {urllib.parse.urlsplit(url).path}: {error}") from error


def _slice(data: bytes) -> str:
    text = data[:BODY_SLICE_BYTES].decode("utf-8", "replace")
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)


class Api:
    """Bounded REST access to exactly this repository, every call logged."""

    def __init__(self, token: str, budget: int, transport: Transport = urllib_transport):
        require(isinstance(token, str) and token != "", "release token missing")
        self.token = token
        self.budget = budget
        self.transport = transport
        self.calls = 0
        self.deadline = time.monotonic() + DEADLINE_SECONDS

    def send(self, method: str, url: str, *, body: bytes | None = None,
             accept: str = "application/vnd.github+json", content_type: str | None = None,
             auth: bool = True) -> tuple[int, dict, bytes]:
        self.calls += 1
        require(self.calls <= self.budget, f"API request budget {self.budget} exhausted")
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, f"API deadline of {DEADLINE_SECONDS} s exhausted")
        headers = {"Accept": accept, "X-GitHub-Api-Version": C.GITHUB_API_VERSION,
                   "User-Agent": "platform-release-tip"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        if content_type:
            headers["Content-Type"] = content_type
        status, response_headers, data = self.transport(method, url, headers, body, min(30.0, remaining))
        path = urllib.parse.urlsplit(url).path
        log(f"RELEASE_API {method} {path} status={status} bytes={len(data)}", summary=False)
        require(len(data) <= MAX_JSON_BYTES, f"{method} {path} response exceeds its byte budget")
        return status, response_headers, data

    def json(self, method: str, path: str, *, payload: object | None = None,
             expect: tuple[int, ...] = (200,), absent: bool = False) -> object:
        require(path == "" or (path.startswith("/") and ".." not in path
                               and re.fullmatch(r"[A-Za-z0-9._~%?&=/,-]*", path) is not None),
                "foreign API path")
        body = None if payload is None else json.dumps(payload, sort_keys=True).encode()
        status, _, data = self.send(method, API_ROOT + API_REPOSITORY + path, body=body,
                                    content_type="application/json" if body is not None else None)
        if absent and status == 404:
            return None
        require(status in expect, f"{method} {path} returned HTTP {status}: {_slice(data)}")
        return json.loads(data) if data else None

    def asset(self, asset_id: int, limit: int) -> bytes:
        """Download one asset; the signed redirect never receives the token."""
        path = f"{API_ROOT}{API_REPOSITORY}/releases/assets/{positive(asset_id)}"
        status, headers, data = self.send("GET", path, accept="application/octet-stream")
        if status in (301, 302, 307):
            location = headers.get("Location") or headers.get("location") or ""
            target = urllib.parse.urlsplit(location)
            require(target.scheme == "https" and target.hostname in ASSET_HOSTS
                    and target.port in (None, 443) and not target.username and not target.password
                    and not target.fragment, "identity asset redirect is foreign")
            status, _, data = self.send("GET", location, accept="application/octet-stream", auth=False)
        require(status == 200, f"identity asset {asset_id} download returned HTTP {status}: {_slice(data)}")
        require(0 < len(data) <= limit, "identity asset size exceeds its budget")
        return data

    def upload(self, release_id: int, name: str, payload: bytes) -> dict:
        url = f"{UPLOAD_PREFIX}{positive(release_id)}/assets?name={urllib.parse.quote(name)}"
        status, _, data = self.send("POST", url, body=payload, content_type="application/json")
        require(status == 201, f"asset upload {name} returned HTTP {status}: {_slice(data)}")
        return json.loads(data)


def positive(value: object) -> int:
    require(type(value) is int and value > 0, "identifier is not a positive integer")
    return value  # type: ignore[return-value]


def git(root: Path, *args: str) -> str:
    value = C._git(root, *args)
    require(isinstance(value, str), f"git {' '.join(args)} returned nothing")
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------- context


def context(environment: dict, root: Path) -> dict:
    """Bind the run to the protected-main publisher executing at its own tip."""
    require(environment.get("GITHUB_API_URL") == API_ROOT, "foreign API")
    require(environment.get("GITHUB_REPOSITORY") == E.NEW_REPOSITORY, "foreign repository")
    require(environment.get("GITHUB_REPOSITORY_ID") == str(E.REPOSITORY_ID), "foreign repository object")
    event = environment.get("GITHUB_EVENT_NAME")
    require(event in E.TIP_PUBLISHER_EVENTS, f"publisher trigger {event!r} is foreign")
    require(environment.get("GITHUB_REF") == C.PROTECTED_REF, "publisher must run on protected main")
    require(environment.get("GITHUB_WORKFLOW_REF")
            == f"{E.NEW_REPOSITORY}/{E.PUBLISHER_WORKFLOW}@{C.PROTECTED_REF}", "foreign publisher workflow")
    source = C.require_sha(environment.get("GITHUB_SHA"), "publisher source SHA")
    require(environment.get("GITHUB_WORKFLOW_SHA") == source, "workflow and source SHA differ")
    require(git(root, "rev-parse", "HEAD") == source, "checkout differs from the publisher source")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]*", run_id) is not None
            and re.fullmatch(r"[1-9][0-9]*", attempt) is not None, "foreign run identity")
    if event == "workflow_run":
        with Path(environment["GITHUB_EVENT_PATH"]).open("rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
        require(len(raw) <= MAX_JSON_BYTES, "event exceeds its byte budget")
        # The completed run is only the wake-up; the tip is always re-derived.
        C.plan_workflow_run(json.loads(raw), E.NEW_REPOSITORY)
    return {"source_sha": source, "event": event, "run_id": int(run_id), "run_attempt": int(attempt)}


def main_tip(api: Api) -> str:
    ref = api.json("GET", "/git/ref/heads/main")
    require(isinstance(ref, dict) and ref.get("ref") == C.PROTECTED_REF
            and isinstance(ref.get("object"), dict) and ref["object"].get("type") == "commit",
            "protected main ref is malformed")
    return C.require_sha(ref["object"].get("sha"), "protected main SHA")


# ---------------------------------------------------------------- CI


def _listing(api: Api, workflow: str, source: str) -> dict:
    value = api.json("GET", f"/actions/workflows/{workflow}/runs?branch=main&event=push"
                            f"&head_sha={source}&per_page=100")
    require(isinstance(value, dict) and set(value) == {"total_count", "workflow_runs"}
            and type(value["total_count"]) is int and isinstance(value["workflow_runs"], list),
            f"{workflow} run listing is malformed")
    return value


def _ci_state(run: dict) -> str:
    status, conclusion = run.get("status"), run.get("conclusion")
    if status in IN_FLIGHT:
        return "pending"
    return "success" if (status, conclusion) == ("completed", "success") else f"red:{conclusion}"


def prove_ci(api: Api, source: str, *, sleep: Callable[[float], None] = time.sleep) -> tuple:
    """Return ("ok", run_id, attempt) or ("pending"|"red", reason) for the tip."""
    main = _listing(api, "pull-request.yml", source)
    if main["total_count"] == 0:
        return ("pending", "main CI has not started")
    require(main["total_count"] == 1 and len(main["workflow_runs"]) == 1,
            "expected exactly one main CI push run for the tip")
    run = main["workflow_runs"][0]
    require(isinstance(run, dict), "main CI run record is malformed")
    state = _ci_state(run)
    if state != "success":
        return ("pending", "main CI is running") if state == "pending" else ("red", f"main CI {state}")
    require(C.plan_workflow_run({"repository": run.get("repository"), "workflow_run": run},
                                E.NEW_REPOSITORY) == source, "main CI run source differs")
    run_id, attempt = positive(run.get("id")), positive(run.get("run_attempt"))
    jobs = api.json("GET", f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    for poll in range(CODEQL_POLLS):
        codeql = _listing(api, "codeql.yml", source)
        runs = codeql["workflow_runs"]
        if len(runs) == 1 and isinstance(runs[0], dict) and _ci_state(runs[0]).startswith("red"):
            return ("red", f"CodeQL {_ci_state(runs[0])}")
        selected = C.classify_codeql_run(codeql, source)
        if selected is not None:
            codeql_jobs = api.json("GET", f"/actions/runs/{selected[0]}/attempts/{selected[1]}"
                                          "/jobs?per_page=100")
            if C.codeql_jobs_ready(codeql_jobs, run_id=selected[0], run_attempt=selected[1],
                                   source_sha=source):
                C.build_main_ci_jobs_receipt(jobs, codeql, codeql_jobs, E.NEW_REPOSITORY,
                                             str(run_id), str(attempt), source)
                return ("ok", run_id, attempt)
        if poll + 1 < CODEQL_POLLS:
            sleep(CODEQL_POLL_SECONDS)
    return ("pending", "CodeQL has not completed")


# ---------------------------------------------------------------- ledger and content


def fragments(root: Path, base_sha: str, source: str) -> tuple:
    """Every fragment added since the predecessor, in canonical path order."""
    intents = C._release_surface_intents(root, base_sha, source)
    return tuple((intent.fragment_path, intent.fragment_sha256) for intent in intents)


def render_notes(root: Path, tag: str, source: str, base_tag: str, bound: tuple) -> str:
    header = (
        f"## Platform {tag}\n\n"
        f"Immutable repository source: `{source}`\n\n"
        "This release names platform source only. It does not deploy, promote, "
        "mutate a cluster, edge provider, DNS, Tunnel, secret, or protected custody.\n\n"
        f"Fragments since {base_tag}: {len(bound)}\n"
    )
    full = header + "".join(
        f"\n### `{path}` (`sha256:{digest}`)\n\n"
        + C.validate_fragment_bytes(path, C._file_bytes(root, source, path))
        for path, digest in bound
    )
    if len(full.encode("utf-8")) <= NOTES_BUDGET_BYTES:
        return full
    return header + "".join(f"\n- `{path}` (`sha256:{digest}`)" for path, digest in bound) + (
        "\n\nThe fragment texts exceed the Release notes budget; read them at this tag.\n"
    )


def render_identity(root: Path, *, tag: str, source: str, base_tag: str, base_sha: str,
                    bound: tuple, tag_object_sha: str, release_id: int, main_run: tuple,
                    platform_run: tuple, event: str) -> bytes:
    """The canonical signed v5 identity; verification re-renders and compares bytes."""
    selected = E.identity(tag)
    require(selected["version"] == 5, "tip publication only renders v5 identities")
    require(event in E.TIP_PUBLISHER_EVENTS, "publisher event is foreign")
    require(bool(bound), "a tip Release binds at least one fragment")
    evidence = {
        "changelog": {"fragments": [{"path": path, "sha256": f"sha256:{digest}"}
                                    for path, digest in bound]},
        "main_ci": {"conclusion": "success", "event": "push", "head_sha": source,
                    "ref": C.PROTECTED_REF, "run_attempt": positive(main_run[1]),
                    "run_id": positive(main_run[0]), "workflow": C.WORKFLOW_PATH},
        "platform_release": {"event": event, "head_sha": source, "job": E.EVIDENCE_JOB,
                             "ref": C.PROTECTED_REF, "run_attempt": positive(platform_run[1]),
                             "run_id": positive(platform_run[0]), "workflow": E.PUBLISHER_WORKFLOW},
        "predecessor": {"peeled_commit": C.require_sha(base_sha, "predecessor SHA"), "tag": base_tag},
        "release": {"asset_count": 2, "draft": False, "id": positive(release_id), "immutable": True,
                    "prerelease": False, "tag_name": tag, "target_commitish": source},
        "repository": selected["repository"],
        "repository_id": E.REPOSITORY_ID,
        "schema": selected["schema"],
        "source": {"merge_sha": source, "protected_ref": C.PROTECTED_REF,
                   "tree_sha": git(root, "rev-parse", f"{source}^{{tree}}")},
        "tag": {"name": tag, "object_sha": C.require_sha(tag_object_sha, "tag object SHA"),
                "object_type": "tag", "peeled_commit": source},
    }
    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag, base_tag, base_sha, source)
    E.validate_identity(evidence)
    rendered = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    payload = rendered.encode("utf-8")
    require(len(payload) <= C.MAX_RELEASE_IDENTITY_BYTES, "v5 identity exceeds 64 KiB")
    return payload


def tag_message(tag: str, source: str) -> str:
    return f"Platform release {tag} from {source}"


# ---------------------------------------------------------------- provider proofs


def exact_run(api: Api, run_id: int, attempt: int) -> dict:
    value = api.json("GET", f"/actions/runs/{positive(run_id)}/attempts/{positive(attempt)}")
    require(isinstance(value, dict) and (value.get("id"), value.get("run_attempt")) == (run_id, attempt),
            "run attempt substitution")
    for field in ("repository", "head_repository"):
        repository = value.get(field)
        require(isinstance(repository, dict), "run repository absent")
        E.repository(repository.get("full_name"), repository.get("id"))
        require(repository.get("full_name") == E.NEW_REPOSITORY, "run repository name differs")
    return value


def prove_evidence_job(api: Api, identity: dict, source: str, *, polls: int = 1,
                       sleep: Callable[[float], None] = time.sleep) -> None:
    """The v5 finalization proof: the named evidence job completed successfully.

    The run's overall conclusion is deliberately not consulted: a failure after
    the immutable flip must not make the Release unverifiable, and a later
    attempt can never stand in for the attempt the signed identity names.
    Only a job still reported in flight is re-read, and only ``polls`` times.
    """
    run = identity["platform_release"]
    record = exact_run(api, run["run_id"], run["run_attempt"])
    require(record.get("event") == run["event"] and record.get("path") == E.PUBLISHER_WORKFLOW
            and record.get("head_sha") == source and record.get("head_branch") == "main",
            "publisher run record differs from the signed identity")
    for poll in range(polls):
        jobs = api.json("GET", f"/actions/runs/{run['run_id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
        require(isinstance(jobs, dict) and isinstance(jobs.get("jobs"), list), "publisher job listing is malformed")
        matches = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == E.EVIDENCE_JOB]
        require(len(matches) == 1, "the signed evidence job is absent or ambiguous")
        job = matches[0]
        require((job.get("run_id"), job.get("run_attempt"), job.get("head_sha"), job.get("head_branch"),
                 job.get("workflow_name")) == (run["run_id"], run["run_attempt"], source, "main", WORKFLOW_NAME),
                "evidence job identity differs from the signed identity")
        if job.get("status") not in IN_FLIGHT or poll + 1 == polls:
            break
        sleep(poll + 1)
    require((job.get("status"), job.get("conclusion")) == ("completed", "success"),
            f"evidence job is {job.get('status')}/{job.get('conclusion')}, not completed/success")


def prove_main_ci_record(api: Api, identity: dict, source: str) -> None:
    ci = identity["main_ci"]
    record = exact_run(api, ci["run_id"], ci["run_attempt"])
    require((record.get("event"), record.get("path"), record.get("head_sha"), record.get("head_branch"),
             record.get("status"), record.get("conclusion"))
            == ("push", C.WORKFLOW_PATH, source, "main", "completed", "success"),
            "main CI attempt named by the identity is not an exact success")


def verify_signature(identity: bytes, bundle: bytes, tag: str, source: str, trigger: str) -> None:
    selected = E.identity(tag)
    with tempfile.TemporaryDirectory(prefix="platform-release-identity-") as scratch:
        path = Path(scratch)
        (path / "identity.json").write_bytes(identity)
        (path / "bundle.json").write_bytes(bundle)
        environment = {key: value for key, value in os.environ.items() if key != "COSIGN_REPOSITORY"}
        result = subprocess.run(
            ["cosign", "verify-blob", "--timeout", "30s", "--bundle", str(path / "bundle.json"),
             "--certificate-identity", selected["subject"],
             "--certificate-oidc-issuer", C.SELECTOR_CERTIFICATE_ISSUER,
             "--certificate-github-workflow-sha", source,
             "--certificate-github-workflow-trigger", trigger, str(path / "identity.json")],
            check=False, timeout=60, capture_output=True, text=True, env=environment)
        require(result.returncode == 0, f"cosign verify-blob refused {tag}: {result.stderr.strip()[-400:]}")


def prove_tag(root: Path, api: Api, tag: str, source: str, ref: dict | None = None) -> str:
    """The exact annotated tag this publisher creates, read back from REST."""
    if ref is None:
        ref = api.json("GET", f"/git/ref/tags/{tag}")
    require(isinstance(ref, dict) and isinstance(ref.get("object"), dict), "tag ref is malformed")
    object_sha = C.require_sha(ref["object"].get("sha"), "tag object SHA")
    annotated = api.json("GET", f"/git/tags/{object_sha}")
    C.validate_tag_record(ref, annotated, tag=tag, source_sha=source, message=tag_message(tag, source),
                          tagger_name=C.RELEASE_TAGGER_NAME, tagger_email=C.RELEASE_TAGGER_EMAIL,
                          tagger_date=git(root, "show", "-s", "--format=%cI", source))
    return object_sha


def download_pair(api: Api, release: dict, tag: str) -> tuple[bytes, bytes]:
    selected = E.identity(tag)
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 2 and all(isinstance(a, dict) for a in assets)
            and {a.get("name") for a in assets} == {selected["asset"], selected["bundle"]},
            f"{tag} Release does not carry exactly its two identity assets")
    by_name = {asset["name"]: asset for asset in assets}
    identity = api.asset(by_name[selected["asset"]].get("id"), C.MAX_RELEASE_IDENTITY_BYTES)
    bundle = api.asset(by_name[selected["bundle"]].get("id"), C.MAX_RELEASE_IDENTITY_BUNDLE_BYTES)
    return identity, bundle


def prove_v5_content(root: Path, api: Api, release: dict, identity: bytes, bundle: bytes, *,
                     tag: str, source: str, base_tag: str, base_sha: str, tag_object_sha: str,
                     staged: bool, evidence_polls: int = 1,
                     sleep: Callable[[float], None] = time.sleep) -> dict:
    """Bind a v5 identity to independently re-derived facts, byte for byte."""
    evidence = C._validate_identity_asset_metadata(release, identity, bundle, staged=staged,
                                                   api_repository=E.NEW_REPOSITORY,
                                                   api_repository_id=E.REPOSITORY_ID)
    runs = {}
    for key in ("main_ci", "platform_release"):
        run = evidence.get(key)
        require(isinstance(run, dict), f"identity {key} is malformed")
        runs[key] = (run.get("run_id"), run.get("run_attempt"))
    event = evidence["platform_release"].get("event")
    require(event in E.TIP_PUBLISHER_EVENTS, "identity publisher event is foreign")
    expected = render_identity(root, tag=tag, source=source, base_tag=base_tag, base_sha=base_sha,
                               bound=fragments(root, base_sha, source), tag_object_sha=tag_object_sha,
                               release_id=release.get("id"), main_run=runs["main_ci"],
                               platform_run=runs["platform_release"], event=event)
    require(identity == expected, f"{tag} identity differs from its re-derived v5 identity")
    verify_signature(identity, bundle, tag, source, event)
    prove_main_ci_record(api, evidence, source)
    prove_evidence_job(api, evidence, source, polls=evidence_polls, sleep=sleep)
    return evidence


def prove_published(root: Path, api: Api, boundary, predecessor, release: dict | None = None) -> None:
    """Prove the latest published Release exactly, v4 checkpoint or v5 tip."""
    tag, source = boundary.tag, boundary.source_sha
    object_sha = prove_tag(root, api, tag, source)
    if release is None:
        release = api.json("GET", f"/releases/tags/{tag}")
    require(isinstance(release, dict), f"{tag} Release record is malformed")
    identity, bundle = download_pair(api, release, tag)
    selected = E.identity(tag)
    tree = git(root, "rev-parse", f"{source}^{{tree}}")
    if selected["version"] == 4:
        # The terminal per-merge Release keeps its original v4 validators.
        require(tag == E.TERMINAL_V4_TAG and source == E.TERMINAL_V4_SOURCE,
                "only the terminal v4 checkpoint precedes tip publication")
        C.validate_identity_release_record(release, identity=identity, bundle=bundle, tag=tag,
                                           source_sha=source, tag_object_sha=object_sha, tree_sha=tree,
                                           api_repository=E.NEW_REPOSITORY,
                                           api_repository_id=E.REPOSITORY_ID)
        value = json.loads(identity)
        verify_signature(identity, bundle, tag, value["execution"]["source_sha"], selected["publisher_event"])
        runs = [exact_run(api, value[key]["run_id"], value[key]["run_attempt"])
                for key in ("main_ci", "platform_release")]
        C.validate_identity_run_records(identity, *runs)
        return
    require(selected["version"] == 5 and predecessor is not None, f"{tag} is not a tip Release")
    require((release.get("tag_name"), release.get("name"), release.get("target_commitish"),
             release.get("draft"), release.get("prerelease"), release.get("immutable"))
            == (tag, f"Platform {tag}", source, False, False, True),
            f"{tag} Release is not the exact immutable published record")
    require(isinstance(release.get("author"), dict)
            and {k: release["author"].get(k) for k in BOT} == BOT, f"{tag} Release author is foreign")
    require(release.get("body") == render_notes(root, tag, source, predecessor.tag,
                                                fragments(root, predecessor.source_sha, source)),
            f"{tag} Release notes are not exact")
    prove_v5_content(root, api, release, identity, bundle, tag=tag, source=source,
                     base_tag=predecessor.tag, base_sha=predecessor.source_sha,
                     tag_object_sha=object_sha, staged=False)


# ---------------------------------------------------------------- admission


def decide(root: Path, api: Api, bound: dict, *, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Return the canonical plan for this run; every branch is one named decision."""
    source = bound["source_sha"]
    ledger = C._platform_tag_boundaries(root)
    latest = ledger[-1]
    release = api.json("GET", f"/releases/tags/{latest.tag}", absent=True)
    terminal = C.Version.parse(E.TERMINAL_V4_TAG.removeprefix("v"))
    if release is None:
        require(latest.version > terminal, f"{latest.tag} has no published Release")
        # Committed but not flipped. Finishing it needs no new signature and so
        # neither the current tip nor its CI; the write job proves the staged
        # evidence before it flips anything.
        return {"decision": "finalize", "tag": latest.tag, "source_sha": latest.source_sha,
                "base_tag": ledger[-2].tag, "base_sha": ledger[-2].source_sha}
    require(latest.version >= terminal, "the ledger predates the terminal v4 checkpoint")
    tip = main_tip(api)
    if tip != source:
        return {"decision": "none", "reason": f"superseded by main {tip}"}
    ci = prove_ci(api, source, sleep=sleep)
    if ci[0] != "ok":
        return {"decision": "none", "reason": f"ci-{ci[0]}: {ci[1]}"}
    prove_published(root, api, latest, ledger[-2] if len(ledger) > 1 else None, release)
    if latest.source_sha == source:
        return {"decision": "none", "reason": f"current: {latest.tag} already releases the tip"}
    bound_fragments = fragments(root, latest.source_sha, source)
    if not bound_fragments:
        return {"decision": "none", "reason": f"current: no fragment since {latest.tag}"}
    return {"decision": "publish", "tag": E.next_tag(latest.tag), "source_sha": source,
            "base_tag": latest.tag, "base_sha": latest.source_sha,
            "main_run_id": ci[1], "main_run_attempt": ci[2], "fragments": len(bound_fragments)}


def encode_plan(plan: dict, bound: dict) -> str:
    value = {"schema": PLAN_SCHEMA, "run_id": bound["run_id"], "run_attempt": bound["run_attempt"],
             "event": bound["event"], **plan}
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def read_plan(supplied: str | None, bound: dict, decision: str) -> dict:
    require(isinstance(supplied, str) and 0 < len(supplied) <= 4096, "release plan is absent")
    value = json.loads(supplied)
    require(isinstance(value, dict) and json.dumps(value, sort_keys=True, separators=(",", ":")) == supplied,
            "release plan is not canonical JSON")
    require(value.get("schema") == PLAN_SCHEMA and value.get("decision") == decision,
            f"release plan is not a {decision} plan")
    require((value.get("run_id"), value.get("run_attempt"), value.get("event"))
            == (bound["run_id"], bound["run_attempt"], bound["event"]),
            "release plan belongs to another run or attempt")
    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, value["tag"], value["base_tag"],
                  value["base_sha"], value["source_sha"])
    return value


# ---------------------------------------------------------------- writes


def release_pages(api: Api) -> list:
    records: list = []
    for page in range(1, RELEASE_PAGES + 1):
        value = api.json("GET", f"/releases?per_page=100&page={page}")
        require(isinstance(value, list) and all(isinstance(item, dict) for item in value),
                "Release listing is malformed")
        records.extend(value)
        if len(value) < 100:
            return records
    raise Refusal("Release listing exceeds its page bound")


def drafts_for(api: Api, tag: str) -> list:
    """Every mutable record that claims this tag or its title."""
    found = [record for record in release_pages(api)
             if record.get("tag_name") == tag or record.get("name") == f"Platform {tag}"]
    for record in found:
        require(record.get("draft") is True, f"a published Release already claims {tag}")
    return found


def discard_leftovers(api: Api, tag: str) -> None:
    """Pre-commit only: delete this publisher's own drafts for the next tag."""
    leftovers = drafts_for(api, tag)
    require(len(leftovers) <= MAX_DISCARDS, f"{len(leftovers)} drafts claim {tag}; refusing to guess")
    for record in leftovers:
        author = record.get("author")
        require(isinstance(author, dict) and {k: author.get(k) for k in BOT} == BOT,
                f"a foreign draft claims {tag}; refusing to delete it")
        release_id = positive(record.get("id"))
        api.json("DELETE", f"/releases/{release_id}", expect=(204,))
        require(api.json("GET", f"/releases/{release_id}", absent=True) is None,
                f"discarded draft {release_id} is still present")
        log(f"RELEASE_DISCARD tag={tag} draft={release_id} reason=pre-commit-leftover")


def stage(root: Path, api: Api, bound: dict, plan: dict, *, sleep=time.sleep) -> int:
    """The evidence job: stage every byte, sign, and verify before any commit."""
    tag, source = plan["tag"], plan["source_sha"]
    require(source == bound["source_sha"], "stage runs only at its own source")
    require(main_tip(api) == source, "main advanced before staging; the newer tip publishes")
    ledger = C._platform_tag_boundaries(root)
    latest = ledger[-1]
    require((latest.tag, latest.source_sha) == (plan["base_tag"], plan["base_sha"]),
            "the ledger moved since admission")
    prove_published(root, api, latest, ledger[-2] if len(ledger) > 1 else None)
    require(api.json("GET", f"/git/ref/tags/{tag}", absent=True) is None,
            f"{tag} is already committed; the next run finalizes it")
    discard_leftovers(api, tag)
    bound_fragments = fragments(root, plan["base_sha"], source)
    date = git(root, "show", "-s", "--format=%cI", source)
    created = api.json("POST", "/git/tags", expect=(201,), payload={
        "tag": tag, "message": tag_message(tag, source), "object": source, "type": "commit",
        "tagger": {"name": C.RELEASE_TAGGER_NAME, "email": C.RELEASE_TAGGER_EMAIL, "date": date}})
    require(isinstance(created, dict), "tag object response is malformed")
    object_sha = C.require_sha(created.get("sha"), "created tag object SHA")
    # A dangling object is not a commit: the ref below is. Same content, same SHA.
    prove_tag(root, api, tag, source, {"ref": f"refs/tags/{tag}", "object": {"sha": object_sha, "type": "tag"}})
    notes = render_notes(root, tag, source, plan["base_tag"], bound_fragments)
    draft = api.json("POST", "/releases", expect=(201,), payload={
        "tag_name": tag, "target_commitish": source, "name": f"Platform {tag}", "body": notes,
        "draft": True, "prerelease": False})
    require(isinstance(draft, dict), "draft response is malformed")
    release_id = positive(draft.get("id"))
    C.validate_draft_release_record(draft, tag=tag, source_sha=source, title=f"Platform {tag}", body=notes)
    identity = render_identity(root, tag=tag, source=source, base_tag=plan["base_tag"],
                               base_sha=plan["base_sha"], bound=bound_fragments, tag_object_sha=object_sha,
                               release_id=release_id,
                               main_run=(plan["main_run_id"], plan["main_run_attempt"]),
                               platform_run=(bound["run_id"], bound["run_attempt"]), event=bound["event"])
    selected = E.identity(tag)
    with tempfile.TemporaryDirectory(prefix="platform-release-sign-") as scratch:
        path = Path(scratch)
        (path / "identity.json").write_bytes(identity)
        environment = {key: value for key, value in os.environ.items() if key != "COSIGN_REPOSITORY"}
        result = subprocess.run(["cosign", "sign-blob", "--yes", "--bundle", str(path / "bundle.json"),
                                 str(path / "identity.json")],
                                check=False, timeout=120, capture_output=True, text=True, env=environment)
        require(result.returncode == 0, f"cosign sign-blob failed: {result.stderr.strip()[-400:]}")
        bundle = (path / "bundle.json").read_bytes()
    verify_signature(identity, bundle, tag, source, bound["event"])
    api.upload(release_id, selected["asset"], identity)
    api.upload(release_id, selected["bundle"], bundle)
    staged = api.json("GET", f"/releases/{release_id}")
    require(isinstance(staged, dict), "staged draft record is malformed")
    C.validate_draft_release_record(staged, tag=tag, source_sha=source, title=f"Platform {tag}",
                                    body=notes, expected_release_id=release_id, expected_asset_count=2)
    downloaded = download_pair(api, staged, tag)
    require(downloaded == (identity, bundle), "staged assets differ from the signed bytes")
    C._validate_identity_asset_metadata(staged, identity, bundle, staged=True,
                                        api_repository=E.NEW_REPOSITORY, api_repository_id=E.REPOSITORY_ID)
    log(f"RELEASE_STAGED tag={tag} source={source} draft={release_id} tag_object={object_sha} "
        f"fragments={len(bound_fragments)} run={bound['run_id']}:{bound['run_attempt']}")
    return release_id


def find_draft(api: Api, tag: str) -> dict:
    found = drafts_for(api, tag)
    require(len(found) == 1, f"{tag} is committed but {len(found)} drafts claim it")
    return found[0]


def publish(root: Path, api: Api, bound: dict, plan: dict, staged_id: int | None, *,
            sleep: Callable[[float], None] = time.sleep) -> None:
    """Commit (tag ref) and flip, or finalize an earlier committed Release."""
    tag, source = plan["tag"], plan["source_sha"]
    finalizing = plan["decision"] == "finalize"
    record = find_draft(api, tag) if finalizing else api.json("GET", f"/releases/{positive(staged_id)}")
    require(isinstance(record, dict), "staged draft record is malformed")
    release_id = positive(record.get("id"))
    bound_fragments = fragments(root, plan["base_sha"], source)
    notes = render_notes(root, tag, source, plan["base_tag"], bound_fragments)
    C.validate_draft_release_record(record, tag=tag, source_sha=source, title=f"Platform {tag}",
                                    body=notes, expected_release_id=release_id, expected_asset_count=2)
    identity, bundle = download_pair(api, record, tag)
    tag_evidence = C._canonical_release_identity(identity).get("tag")
    require(isinstance(tag_evidence, dict), "staged identity names no tag")
    object_sha = C.require_sha(tag_evidence.get("object_sha"), "staged tag object SHA")
    evidence = prove_v5_content(root, api, record, identity, bundle, tag=tag, source=source,
                                base_tag=plan["base_tag"], base_sha=plan["base_sha"],
                                tag_object_sha=object_sha, staged=True,
                                evidence_polls=READBACK_POLLS, sleep=sleep)
    if not finalizing:
        require((evidence["platform_release"]["run_id"], evidence["platform_release"]["run_attempt"])
                == (bound["run_id"], bound["run_attempt"]), "publish commits only its own run's evidence")
    ref = api.json("GET", f"/git/ref/tags/{tag}", absent=True)
    if ref is None:
        require(not finalizing, f"{tag} lost its committed ref")
        # Never point the commit at an object that is not the exact signed one.
        prove_tag(root, api, tag, source, {"ref": f"refs/tags/{tag}", "object": {"sha": object_sha, "type": "tag"}})
        created = api.json("POST", "/git/refs", expect=(201, 422),
                           payload={"ref": f"refs/tags/{tag}", "sha": object_sha})
        ref = api.json("GET", f"/git/ref/tags/{tag}", absent=True)
        require(ref is not None, f"commit refused for {tag}: {created}")
        log(f"RELEASE_COMMIT tag={tag} tag_object={object_sha}")
    require(prove_tag(root, api, tag, source, ref) == object_sha, f"{tag} ref names a foreign tag object")
    # A lost or failed flip response is judged only by the readback below.
    body = json.dumps({"tag_name": tag, "target_commitish": source, "name": f"Platform {tag}",
                       "body": notes, "draft": False, "prerelease": False}, sort_keys=True).encode()
    status, _, data = api.send("PATCH", f"{API_ROOT}{API_REPOSITORY}/releases/{release_id}",
                               body=body, content_type="application/json")
    if status != 200:
        log(f"RELEASE_FLIP_RESPONSE tag={tag} status={status} body={_slice(data)}")
    # Not yet visible (404) and transient server errors are re-read within the
    # bound; any other answer is judged immediately.
    published = None
    for poll in range(READBACK_POLLS):
        status, _, data = api.send("GET", f"{API_ROOT}{API_REPOSITORY}/releases/tags/{tag}")
        require(status in (200, 404) or status >= 500, f"{tag} readback returned HTTP {status}: {_slice(data)}")
        candidate = json.loads(data) if status == 200 else None
        if isinstance(candidate, dict) and candidate.get("immutable") is True:
            published = candidate
            break
        if poll + 1 < READBACK_POLLS:
            sleep(poll + 1)
    require(published is not None, f"{tag} did not read back as an immutable published Release")
    predecessor = C.TagBoundary(C.Version.parse(plan["base_tag"].removeprefix("v")),
                                plan["base_tag"], plan["base_sha"])
    boundary = C.TagBoundary(C.Version.parse(tag.removeprefix("v")), tag, source)
    prove_published(root, api, boundary, predecessor, published)
    log(f"RELEASE_PUBLISHED tag={tag} source={source} release={release_id} "
        f"fragments={len(bound_fragments)} mode={plan['decision']}")


# ---------------------------------------------------------------- entry point


AMBIENT = ("GH_TOKEN", "GITHUB_TOKEN", "IMMUTABLE_SETTINGS_TOKEN", "ACTIONS_READ_TOKEN",
           "CONTENTS_READ_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def main(argv: list[str] | None = None, *, transport: Transport = urllib_transport,
         sleep: Callable[[float], None] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "stage", "publish"))
    args = parser.parse_args(argv)
    started = time.monotonic()
    # The credential is never inherited by git, cosign or any other child.
    token = os.environ.pop("PLATFORM_RELEASE_TOKEN", "")
    budget = {"admit": ADMIT_BUDGET, "stage": STAGE_BUDGET, "publish": PUBLISH_BUDGET}[args.command]
    api = None
    outcome = "refused"
    try:
        require(not any(os.environ.get(name) for name in AMBIENT), "ambient credential refused")
        root = Path.cwd()
        bound = context(dict(os.environ), root)
        api = Api(token, budget, transport)
        output = os.environ.get("GITHUB_OUTPUT")
        if args.command == "admit":
            plan = decide(root, api, bound, sleep=sleep)
            outcome = plan["decision"]
            log(f"RELEASE_DECISION {plan['decision']} " + " ".join(
                f"{key}={value}" for key, value in sorted(plan.items()) if key != "decision"))
            if output:
                with open(output, "a", encoding="utf-8") as handle:
                    handle.write(f"decision={plan['decision']}\n")
                    if plan["decision"] != "none":
                        handle.write(f"plan={encode_plan(plan, bound)}\n")
            return 0
        if args.command == "stage":
            plan = read_plan(os.environ.get("RELEASE_PLAN"), bound, "publish")
            release_id = stage(root, api, bound, plan, sleep=sleep)
            outcome = "staged"
            if output:
                with open(output, "a", encoding="utf-8") as handle:
                    handle.write(f"release_id={release_id}\n")
            return 0
        # A staged draft ID means this run's evidence job staged it; none means
        # the plan must finalize an earlier committed Release.
        staged_id = os.environ.get("STAGED_RELEASE_ID", "")
        require(staged_id == "" or re.fullmatch(r"[1-9][0-9]*", staged_id) is not None,
                "staged draft ID is malformed")
        decision = "publish" if staged_id else "finalize"
        plan = read_plan(os.environ.get("RELEASE_PLAN"), bound, decision)
        publish(root, api, bound, plan, int(staged_id) if staged_id else None, sleep=sleep)
        outcome = "published"
        return 0
    except (C.ContractError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        log(f"RELEASE_REFUSED command={args.command} check={error}")
        return 1
    finally:
        calls = api.calls if api is not None else 0
        log(f"RELEASE_SUMMARY command={args.command} outcome={outcome} requests={calls}/{budget} "
            f"seconds={time.monotonic() - started:.1f}")


if __name__ == "__main__":
    raise SystemExit(main())
