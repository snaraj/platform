#!/usr/bin/env python3
"""Read-only admission for the finite source backlog; never a general replayer.

The current protected checkout executes this policy. Historical Git objects are
data, and a canonical first-attempt selection crosses jobs without reselection.
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

_spec = importlib.util.spec_from_file_location(
    "recovery_release_contract", Path(__file__).with_name("platform_release_contract.py")
)
C = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = C
_spec.loader.exec_module(C)
E = C.EPOCH

SELECTION_SCHEMA = "https://snaraj.dev/schemas/platform-release-recovery-selection/v1"
API = "https://api.github.com/repos/snaraj/platform"
TERMINAL_TREE = "db18c40ece8fa91f9dfabb7cb99a833a34a30505"
TERMINAL_TAG_OBJECT = "e28add890e0af9b0be7c3a8548dad3b6fb7e9324"
TERMINAL_RELEASE_ID = 384446269
TERMINAL_MAIN_RUN = 34186703418
TERMINAL_PUBLISHER_RUN = 34186887764
MAX_JSON = 2 * 1024 * 1024
MAX_SELECTION = 4096


def require(condition: bool, message: str) -> None:
    if not condition:
        raise C.ContractError(message)


def canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


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
    require(C._git(root, "rev-parse", "HEAD") == bound["executor_sha"], "checkout differs from executor")
    require(bound["executor_sha"] not in {E.TERMINAL_V3_SOURCE, *(v["source_sha"] for v in E.HISTORICAL_RELEASES)},
            "historical source cannot execute recovery")
    require(C._is_ancestor(root, E.HISTORICAL_RELEASES[-1]["source_sha"], bound["executor_sha"]),
            "executor does not descend from the frozen backlog")
    require(C._git(root, "rev-parse", f"{E.TERMINAL_V3_SOURCE}^{{tree}}") == TERMINAL_TREE,
            "terminal tree differs")
    for frozen in E.HISTORICAL_RELEASES:
        sha = frozen["source_sha"]
        require(C._git(root, "rev-list", "--parents", "-n", "1", sha).split() == [sha, frozen["parent_sha"]],
                "historical edge is not the exact single-parent source")
        require(C._git(root, "rev-parse", f"{sha}^{{tree}}") == frozen["tree_sha"], "historical tree differs")
        fragment = C.validate_transition(root, frozen["parent_sha"], sha, first_parent=True)
        require((fragment.fragment_path, fragment.fragment_sha256) ==
                (frozen["fragment_path"], frozen["fragment_sha256"]), "historical fragment differs")
        for path, digest in E.HISTORICAL_WORKFLOWS.items():
            require(hashlib.sha256(C._git_bytes(root, "show", f"{sha}:{path}")).hexdigest() == digest,
                    "historical workflow differs from its closed inventory")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicAPI:
    """Bounded GETs only; asset redirects never receive the API credential."""

    def __init__(self, token: str | None):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)
        self.deadline = time.monotonic() + 240
        self.requests = 0

    def read(self, path: str, *, limit: int = MAX_JSON, asset: bool = False) -> tuple[int, bytes]:
        require(isinstance(path, str) and (path == "" or path.startswith("/")) and
                not any(value in path for value in ("..", "#", "\\", "\r", "\n")), "foreign API path")
        self.requests += 1
        remaining = self.deadline - time.monotonic()
        require(self.requests <= 96 and remaining > 0, "recovery read budget exhausted")
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
                    raise C.ContractError(f"GitHub read refused with HTTP {error.code}") from error
        with response:
            require(response.status == 200, "GitHub read did not return 200")
            value = response.read(limit + 1)
            require(len(value) <= limit, "GitHub response exceeds its byte budget")
            return 200, value

    def get(self, path: str, *, absent: bool = False) -> dict | None:
        status, data = self.read(path)
        if status == 404:
            require(absent, "required GitHub record missing; delivery remains held")
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
    value = api.get(f"/actions/workflows/{workflow}/runs?branch=main&event=push&head_sha={source}&per_page=100")
    require(set(value) == {"total_count", "workflow_runs"} and type(value["total_count"]) is int
            and value["total_count"] == 1 and len(value["workflow_runs"]) == 1,
            "executor needs exactly one complete main workflow listing")
    run = value["workflow_runs"][0]
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


def verify_signature(identity: bytes, bundle: bytes, tag: str) -> None:
    selected = E.identity(tag)
    value = json.loads(identity)
    args = []
    if selected["version"] == 4:
        E.validate_identity(value)
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


def prove_release(root: Path, api: PublicAPI, tag: str, source: str) -> bool:
    """Only an exact immutable release with its ORIGINAL completed run advances."""
    ref = api.get(f"/git/ref/tags/{tag}", absent=True)
    release = api.get(f"/releases/tags/{tag}", absent=True)
    if ref is None:
        require(release is None, "Release without its exact annotated tag")
        return False
    object_sha = C.require_sha(ref.get("object", {}).get("sha"), "tag object")
    annotated = api.get(f"/git/tags/{object_sha}")
    C.validate_tag_record(ref, annotated, tag=tag, source_sha=source,
                          message=f"Platform release {tag} from {source}",
                          tagger_name=C.RELEASE_TAGGER_NAME, tagger_email=C.RELEASE_TAGGER_EMAIL,
                          tagger_date=C._git(root, "show", "-s", "--format=%cI", source))
    require(C._git(root, "rev-parse", f"refs/tags/{tag}") == object_sha, "fetched and API tag objects differ")
    if release is None:
        return False
    selected = E.identity(tag)
    assets = release.get("assets", [])
    require(isinstance(assets, list) and len(assets) == 2,
            "partial or foreign release remains held")
    require(all(isinstance(asset, dict) for asset in assets) and
            {asset.get("name", "") for asset in assets} == {selected["asset"], selected["bundle"]},
            "foreign identity asset names remain held")
    raw = {}
    for asset in assets:
        asset_id = positive(asset.get("id"))
        limit = C.MAX_RELEASE_IDENTITY_BYTES if asset["name"] == selected["asset"] else C.MAX_RELEASE_IDENTITY_BUNDLE_BYTES
        require(type(asset.get("size")) is int and 0 < asset["size"] <= limit, "identity asset size exceeds budget")
        status, data = api.read(f"/releases/assets/{asset_id}", limit=limit, asset=True)
        require(status == 200, "identity asset download failed")
        raw[asset["name"]] = data
    identity, bundle = raw[selected["asset"]], raw[selected["bundle"]]
    C.validate_identity_release_record(release, identity=identity, bundle=bundle, tag=tag, source_sha=source,
                                      tag_object_sha=object_sha, tree_sha=C._git(root, "rev-parse", f"{source}^{{tree}}"),
                                      api_repository=E.NEW_REPOSITORY, api_repository_id=E.REPOSITORY_ID)
    verify_signature(identity, bundle, tag)
    value = json.loads(identity)
    if tag == E.TERMINAL_V3_TAG:
        require((object_sha, release["id"], value["main_ci"]["run_id"], value["main_ci"]["run_attempt"],
                 value["platform_release"]["run_id"], value["platform_release"]["run_attempt"]) ==
                (TERMINAL_TAG_OBJECT, TERMINAL_RELEASE_ID, TERMINAL_MAIN_RUN, 1, TERMINAL_PUBLISHER_RUN, 1),
                "terminal v3 identity differs from the frozen checkpoint")
    runs = [exact_run(api, value[name]["run_id"], value[name]["run_attempt"])
            for name in ("main_ci", "platform_release")]
    executor = None
    if selected["version"] == 4:
        ci = value["execution"]["main_ci"]
        executor = exact_run(api, ci["run_id"], ci["run_attempt"])
    # Pending, failed, cancelled, missing or unknown original publisher refuses.
    # An immutable payload naming a failed attempt has no settlement path here.
    if selected["version"] == 4 and runs[1].get("status") in {"queued", "in_progress", "pending", "requested", "waiting"}:
        C.validate_identity_run_records(identity, *runs, execution_main_run_record=executor, platform_pending=True)
        raise C.PendingRelease("original publisher attempt is still pending; do not advance")
    C.validate_identity_run_records(identity, *runs, execution_main_run_record=executor)
    return True


def binding(root: Path, bound: dict, supplied: str) -> dict:
    """Recheck the fixed receipt locally without changing its selected edge."""
    require(len(supplied.encode()) <= MAX_SELECTION, "selection exceeds its byte budget")
    value = json.loads(supplied)
    require(isinstance(value, dict) and canonical(value) == supplied, "selection must be canonical JSON")
    fields = {"schema", *bound, "source_sha", "tag", "base_sha", "base_tag", "executor_main_run_id",
              "executor_main_run_attempt", "executor_codeql_run_id", "executor_codeql_run_attempt"}
    require(set(value) == fields and value["schema"] == SELECTION_SCHEMA, "foreign selection fields")
    require(all(value[key] == expected and type(value[key]) is type(expected) for key, expected in bound.items()),
            "selection belongs to another executor, run or attempt")
    chosen = E.historical_release(value["tag"])
    require(chosen is not None and value["source_sha"] == chosen["source_sha"], "selection is outside the finite window")
    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, value["tag"], value["base_tag"], value["base_sha"], value["source_sha"])
    window = C.discover_transition_window(root, value["source_sha"])
    require((window.base_tag, window.base_sha, window.intent.tag) ==
            (value["base_tag"], value["base_sha"], value["tag"]), "selected edge no longer matches the ledger")
    for key in ("executor_main_run_id", "executor_main_run_attempt", "executor_codeql_run_id", "executor_codeql_run_attempt"):
        positive(value[key])
    return value


def selection(root: Path, api: PublicAPI, bound: dict, supplied: str | None = None) -> dict:
    prove_context(root, api, bound)
    if supplied is None:
        main = run_tuple(api, bound["executor_sha"], "pull-request.yml")
        codeql = run_tuple(api, bound["executor_sha"], "codeql.yml")
        chosen = None
        require(prove_release(root, api, E.TERMINAL_V3_TAG, E.TERMINAL_V3_SOURCE), "terminal v3 Release missing")
        tag = E.FIRST_V4_TAG
        for frozen in E.HISTORICAL_RELEASES:
            if not prove_release(root, api, tag, frozen["source_sha"]):
                chosen = frozen
                break
            tag = E.next_tag(tag)
        require(chosen is not None, "finite recovery backlog is complete; use the ordinary publisher")
        window = C.discover_transition_window(root, chosen["source_sha"])
        require(window.intent.tag == tag and window.base_sha == chosen["parent_sha"], "derived ledger edge differs")
        value = {"schema": SELECTION_SCHEMA, **bound, "source_sha": chosen["source_sha"], "tag": tag,
                 "base_sha": window.base_sha, "base_tag": window.base_tag,
                 "executor_main_run_id": main[0], "executor_main_run_attempt": main[1],
                 "executor_codeql_run_id": codeql[0], "executor_codeql_run_attempt": codeql[1]}
    else:
        value = binding(root, bound, supplied)
        chosen = E.historical_release(value["tag"])
        require(prove_release(root, api, value["base_tag"], value["base_sha"]), "selected predecessor remains incomplete")
        main = (positive(value["executor_main_run_id"]), positive(value["executor_main_run_attempt"]))
        codeql = (positive(value["executor_codeql_run_id"]), positive(value["executor_codeql_run_attempt"]))
    prove_ci(api, bound["executor_sha"], C._git(root, "rev-parse", f"{bound['executor_sha']}^{{tree}}"), main, codeql)
    prove_ci(api, chosen["source_sha"], chosen["tree_sha"], (chosen["main_run_id"], 1), (chosen["codeql_run_id"], 1))
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "bind", "predecessor"))
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
        require((args.command in {"verify", "bind"}) == (supplied is not None), "selection mode differs")
        if args.command == "bind":
            prove_trees(Path.cwd(), bound)
            value = binding(Path.cwd(), bound, supplied)
            for field in ("source_sha", "tag", "base_sha", "base_tag"):
                require(os.environ.get(field.upper()) == value[field], "publisher differs from selected edge")
            chosen = E.historical_release(value["tag"])
            require(os.environ.get("MAIN_RUN_ID") == str(chosen["main_run_id"]) and os.environ.get("MAIN_RUN_ATTEMPT") == "1",
                    "publisher original CI differs")
            require(os.environ.get("EXECUTION_MAIN_RUN_ID") == str(value["executor_main_run_id"])
                    and os.environ.get("EXECUTION_MAIN_RUN_ATTEMPT") == str(value["executor_main_run_attempt"]),
                    "publisher executor CI differs")
            print("RECOVERY_BINDING=PASS")
            return 0
        value = selection(Path.cwd(), PublicAPI(token), bound, supplied)
        encoded = canonical(value)
        require(len(encoded.encode()) <= MAX_SELECTION, "selection exceeds its byte budget")
        if args.command == "prepare":
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                output.write(f"selection={encoded}\nsource_sha={value['source_sha']}\n")
        print(f"RECOVERY_SELECTION=PASS source={value['source_sha']} executor={value['executor_sha']} run={value['run_id']}:1")
        return 0
    except C.PendingRelease as error:
        print(f"recovery pending: {error}", file=sys.stderr)
        return 3
    except (C.ContractError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"recovery refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
