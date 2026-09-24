"""Behavioral tests of tip-only publication (issue #397).

Every test drives the real ``platform_release_tip.main`` entry point, its CLI
parsing, context binding, validators and git derivation against a real git
fixture. Only the provider boundaries are fake: GitHub is a stateful model that
refuses what GitHub refuses (writes to an immutable Release, a second ref, a
redirect carrying the API credential), and ``cosign`` is a PATH shim that binds
a signature to the runner's workflow identity exactly as Fulcio would.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "platform_release_tip_under_test", ROOT / "scripts" / "ci" / "platform_release_tip.py"
)
assert SPEC and SPEC.loader
TIP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TIP
SPEC.loader.exec_module(TIP)
C = TIP.C
E = TIP.E

REPOSITORY = "snaraj/platform"
BOT = {"login": "github-actions[bot]", "id": 41898282}
API = "https://api.github.com/repos/snaraj/platform"
SUBJECT = f"https://github.com/{REPOSITORY}/.github/workflows/platform-release.yml@refs/heads/main"

# A PATH shim standing in for Sigstore: sign-blob binds the digest to the
# workflow identity in the runner environment; verify-blob refuses any
# mismatch of digest, subject, issuer, workflow SHA or trigger.
FAKE_COSIGN = r'''#!/usr/bin/env python3
import base64, hashlib, json, os, sys
args = sys.argv[1:]
def value(flag):
    return args[args.index(flag) + 1] if flag in args else None
if args[0] == "sign-blob":
    payload = open(args[-1], "rb").read()
    claims = {"subject": "https://github.com/" + os.environ["GITHUB_WORKFLOW_REF"],
              "issuer": "https://token.actions.githubusercontent.com",
              "sha": os.environ["GITHUB_WORKFLOW_SHA"], "trigger": os.environ["GITHUB_EVENT_NAME"]}
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "messageSignature": {"messageDigest": {"algorithm": "SHA2_256",
                  "digest": base64.b64encode(hashlib.sha256(payload).digest()).decode()},
                  "signature": base64.b64encode(b"signature").decode()},
              "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(
                  json.dumps(claims, sort_keys=True).encode()).decode()}, "tlogEntries": [{"logIndex": "1"}]}}
    open(value("--bundle"), "w").write(json.dumps(bundle, sort_keys=True))
    sys.exit(0)
if args[0] == "verify-blob":
    payload = open(args[-1], "rb").read()
    bundle = json.load(open(value("--bundle")))
    claims = json.loads(base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"]))
    digest = base64.b64decode(bundle["messageSignature"]["messageDigest"]["digest"])
    expected = {"subject": value("--certificate-identity"), "issuer": value("--certificate-oidc-issuer"),
                "sha": value("--certificate-github-workflow-sha"),
                "trigger": value("--certificate-github-workflow-trigger")}
    if digest != hashlib.sha256(payload).digest() or claims != expected:
        print("error: none of the expected identities matched", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
sys.exit(2)
'''


def fake_bundle(payload: bytes, *, subject: str, sha: str, trigger: str) -> bytes:
    """The same envelope the shim writes, for pre-seeded historical Releases."""
    claims = {"subject": subject, "issuer": C.SELECTOR_CERTIFICATE_ISSUER, "sha": sha, "trigger": trigger}
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {"messageDigest": {"algorithm": "SHA2_256",
                                               "digest": base64.b64encode(hashlib.sha256(payload).digest()).decode()},
                             "signature": base64.b64encode(b"signature").decode()},
        "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(
            json.dumps(claims, sort_keys=True).encode()).decode()}, "tlogEntries": [{"logIndex": "1"}]},
    }
    return json.dumps(bundle, sort_keys=True).encode()


class FakeGitHub:
    """A stateful model of the REST surface the publisher uses."""

    def __init__(self, root: Path):
        self.root = root
        self.main = ""
        self.releases: dict[int, dict] = {}
        self.assets: dict[int, bytes] = {}
        self.runs: dict[tuple[int, int], dict] = {}
        self.jobs: dict[tuple[int, int], list] = {}
        self.listings: dict[tuple[str, str], list] = {}
        self.faults: list[list] = []
        self.on_publish = None
        self.requests: list[tuple[str, str]] = []
        self.next_id = 5000

    def git(self, *args: str, data: bytes | None = None) -> str:
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, input=data,
                              stdout=subprocess.PIPE).stdout.decode().strip()

    def new_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def fault(self, method: str, pattern: str, action: str) -> None:
        self.faults.append([method, re.compile(pattern), action])

    # -- Actions ------------------------------------------------------------

    def repository(self) -> dict:
        return {"full_name": REPOSITORY, "id": E.REPOSITORY_ID}

    def green(self, sha: str, *, main_conclusion: str = "success", main_status: str = "completed",
              codeql_conclusion: str | None = "success", codeql_status: str = "completed",
              attempt: int = 1) -> int:
        run_id = self.new_id()
        tree = self.git("rev-parse", f"{sha}^{{tree}}")
        record = {"id": run_id, "run_attempt": attempt, "name": "Pull request",
                  "path": C.WORKFLOW_PATH, "event": "push", "status": main_status,
                  "conclusion": main_conclusion if main_status == "completed" else None,
                  "head_branch": "main", "head_sha": sha, "head_commit": {"id": sha, "tree_id": tree},
                  "repository": self.repository(), "head_repository": self.repository()}
        self.runs[(run_id, attempt)] = record
        self.listings[("pull-request.yml", sha)] = [record]
        common = {"run_id": run_id, "run_attempt": attempt, "head_sha": sha, "head_branch": "main",
                  "workflow_name": "Pull request", "status": "completed"}
        self.jobs[(run_id, attempt)] = [
            {**common, "id": self.new_id(), "name": "repository-and-infrastructure",
             "conclusion": "success",
             "steps": [{"name": n, "conclusion": c} for n, c in C.MAIN_CI_EXACT_STEPS]},
            {**common, "id": self.new_id(), "name": "dependency-review", "conclusion": "skipped",
             "steps": []}]
        if codeql_conclusion is not None:
            codeql_id = self.new_id()
            codeql = {"id": codeql_id, "run_attempt": 1, "name": "CodeQL", "path": C.CODEQL_WORKFLOW_PATH,
                      "event": "push", "status": codeql_status,
                      "conclusion": codeql_conclusion if codeql_status == "completed" else None,
                      "head_branch": "main", "head_sha": sha}
            self.listings[("codeql.yml", sha)] = [codeql]
            self.jobs[(codeql_id, 1)] = [
                {"id": self.new_id(), "name": name, "run_id": codeql_id, "run_attempt": 1, "head_sha": sha,
                 "head_branch": "main", "workflow_name": "CodeQL", "status": "completed",
                 "conclusion": "success", "steps": [{"name": n, "conclusion": c} for n, c in steps]}
                for name, steps in C.CODEQL_EXACT_STEPS.items()]
        return run_id

    def publisher_run(self, run_id: int, attempt: int, sha: str, event: str) -> None:
        self.runs[(run_id, attempt)] = {
            "id": run_id, "run_attempt": attempt, "name": "Platform release", "path": E.PUBLISHER_WORKFLOW,
            "event": event, "status": "in_progress", "conclusion": None, "head_branch": "main",
            "head_sha": sha, "repository": self.repository(), "head_repository": self.repository()}
        self.jobs.setdefault((run_id, attempt), [])

    def finish_job(self, run_id: int, attempt: int, name: str, conclusion: str) -> None:
        record = self.runs[(run_id, attempt)]
        self.jobs[(run_id, attempt)] = [job for job in self.jobs[(run_id, attempt)] if job["name"] != name] + [{
            "id": self.new_id(), "name": name, "run_id": run_id, "run_attempt": attempt,
            "head_sha": record["head_sha"], "head_branch": "main", "workflow_name": "Platform release",
            "status": "completed", "conclusion": conclusion}]

    # -- Git data -------------------------------------------------------------

    def tag_record(self, sha: str) -> dict | None:
        try:
            if self.git("cat-file", "-t", sha) != "tag":
                return None
        except subprocess.CalledProcessError:
            return None
        raw = self.git("cat-file", "-p", sha)
        header, _, message = raw.partition("\n\n")
        fields = dict(line.split(" ", 1) for line in header.splitlines())
        name, email, stamp, zone = re.fullmatch(r"(.*) <(.*)> (\d+) ([+-]\d{4})", fields["tagger"]).groups()
        offset = dt.timezone(dt.timedelta(hours=int(zone[:3]), minutes=int(zone[0] + zone[3:])))
        date = dt.datetime.fromtimestamp(int(stamp), offset).isoformat()
        return {"sha": sha, "tag": fields["tag"], "message": message,
                "tagger": {"name": name, "email": email, "date": date},
                "object": {"sha": fields["object"], "type": fields["type"]}}

    def ref_record(self, tag: str) -> dict | None:
        try:
            sha = self.git("rev-parse", "-q", "--verify", f"refs/tags/{tag}")
        except subprocess.CalledProcessError:
            return None
        return {"ref": f"refs/tags/{tag}", "object": {"sha": sha, "type": self.git("cat-file", "-t", sha)}}

    # -- Releases -------------------------------------------------------------

    def asset_record(self, release: dict, asset_id: int, name: str, payload: bytes) -> dict:
        return {"id": asset_id, "name": name, "label": "", "state": "uploaded",
                "content_type": "application/json", "size": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "download_count": 0,
                "url": f"{API}/releases/assets/{asset_id}",
                "browser_download_url": self.download_url(release, name), "uploader": dict(BOT)}

    def download_url(self, release: dict, name: str) -> str:
        tag = release["untagged"] if release["draft"] else release["tag_name"]
        return f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"

    def public(self, release: dict) -> dict:
        record = {key: value for key, value in release.items() if key != "untagged"}
        record["assets"] = [dict(asset, browser_download_url=self.download_url(release, asset["name"]))
                            for asset in release["assets"]]
        return record

    def seed_release(self, tag: str, source: str, body: str, files: dict[str, bytes]) -> dict:
        release_id = self.new_id()
        release = {"id": release_id, "tag_name": tag, "target_commitish": source, "name": f"Platform {tag}",
                   "body": body, "draft": False, "prerelease": False, "immutable": True, "author": dict(BOT),
                   "untagged": "untagged-" + "0" * 20, "assets": [],
                   "upload_url": f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets{{?name,label}}"}
        for name, payload in files.items():
            asset_id = self.new_id()
            self.assets[asset_id] = payload
            release["assets"].append(self.asset_record(release, asset_id, name, payload))
        self.releases[release_id] = release
        return release

    def published(self, tag: str) -> dict | None:
        found = [r for r in self.releases.values() if r["tag_name"] == tag and not r["draft"]]
        return found[0] if found else None

    # -- Transport ------------------------------------------------------------

    def __call__(self, method: str, url: str, headers: dict, body: bytes | None, timeout: float):
        parts = urllib.parse.urlsplit(url)
        self.requests.append((method, parts.path + ("?" + parts.query if parts.query else "")))
        if parts.hostname == "release-assets.githubusercontent.com":
            assert "Authorization" not in headers, "the API credential followed an asset redirect"
            return 200, {}, self.assets[int(parts.path.rsplit("/", 1)[1])]
        assert headers.get("Authorization") == "Bearer test-token"
        for fault in self.faults:
            if fault[0] == method and fault[1].search(parts.path):
                self.faults.remove(fault)
                if fault[2] == "drop":
                    self.route(method, parts, body)
                    return 502, {}, b'{"message":"Bad Gateway"}'
                status = int(fault[2])
                return status, {}, json.dumps({"message": f"injected {status}"}).encode()
        return self.route(method, parts, body)

    def reply(self, status: int, value: object = None):
        return status, {}, b"" if value is None else json.dumps(value).encode()

    def route(self, method: str, parts, body: bytes | None):
        query = dict(urllib.parse.parse_qsl(parts.query))
        if parts.hostname == "uploads.github.com":
            release_id = int(re.fullmatch(rf"/repos/{REPOSITORY}/releases/(\d+)/assets", parts.path).group(1))
            release = self.releases[release_id]
            if not release["draft"] or any(a["name"] == query["name"] for a in release["assets"]):
                return self.reply(422, {"message": "immutable or duplicate asset"})
            asset_id = self.new_id()
            self.assets[asset_id] = body
            asset = self.asset_record(release, asset_id, query["name"], body)
            release["assets"].append(asset)
            return self.reply(201, asset)
        path = parts.path.removeprefix(f"/repos/{REPOSITORY}")
        payload = json.loads(body) if body else None
        if method == "GET" and path == "/git/ref/heads/main":
            return self.reply(200, {"ref": "refs/heads/main", "object": {"sha": self.main, "type": "commit"}})
        if match := re.fullmatch(r"/git/ref/tags/(v[0-9.]+)", path):
            record = self.ref_record(match.group(1))
            return self.reply(200, record) if record else self.reply(404, {"message": "Not Found"})
        if match := re.fullmatch(r"/git/tags/([0-9a-f]{40})", path):
            record = self.tag_record(match.group(1))
            return self.reply(200, record) if record else self.reply(404, {"message": "Not Found"})
        if method == "POST" and path == "/git/tags":
            date = dt.datetime.fromisoformat(payload["tagger"]["date"])
            content = (f"object {payload['object']}\ntype {payload['type']}\ntag {payload['tag']}\n"
                       f"tagger {payload['tagger']['name']} <{payload['tagger']['email']}> "
                       f"{int(date.timestamp())} {date.strftime('%z')}\n\n{payload['message']}")
            sha = self.git("hash-object", "-t", "tag", "-w", "--stdin", data=content.encode())
            return self.reply(201, {"sha": sha})
        if method == "POST" and path == "/git/refs":
            name = payload["ref"].removeprefix("refs/tags/")
            if self.ref_record(name) is not None:
                return self.reply(422, {"message": "Reference already exists"})
            self.git("update-ref", payload["ref"], payload["sha"])
            return self.reply(201, self.ref_record(name))
        if match := re.fullmatch(r"/releases/tags/(v[0-9.]+)", path):
            release = self.published(match.group(1))
            return self.reply(200, self.public(release)) if release else self.reply(404, {"message": "Not Found"})
        if method == "GET" and path == "/releases":
            records = sorted(self.releases.values(), key=lambda r: -r["id"])
            page = int(query["page"])
            return self.reply(200, [self.public(r) for r in records[(page - 1) * 100:page * 100]])
        if method == "POST" and path == "/releases":
            release_id = self.new_id()
            release = {"id": release_id, "tag_name": payload["tag_name"],
                       "target_commitish": payload["target_commitish"], "name": payload["name"],
                       "body": payload["body"], "draft": True, "prerelease": False, "immutable": False,
                       "author": dict(BOT), "untagged": "untagged-" + os.urandom(10).hex(), "assets": [],
                       "upload_url": f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets{{?name,label}}"}
            self.releases[release_id] = release
            return self.reply(201, self.public(release))
        if match := re.fullmatch(r"/releases/(\d+)", path):
            release = self.releases.get(int(match.group(1)))
            if release is None:
                return self.reply(404, {"message": "Not Found"})
            if method == "GET":
                return self.reply(200, self.public(release))
            if method == "DELETE":
                del self.releases[release["id"]]
                return self.reply(204)
            if method == "PATCH":
                if not release["draft"]:
                    return self.reply(422, {"message": "immutable release"})
                release.update({k: v for k, v in payload.items() if k != "draft"})
                if payload.get("draft") is False:
                    if self.ref_record(release["tag_name"]) is None:
                        # GitHub would mint a lightweight tag at the target.
                        self.git("update-ref", f"refs/tags/{release['tag_name']}", release["target_commitish"])
                    release.update(draft=False, immutable=True)
                    if self.on_publish is not None:
                        self.on_publish(release)
                return self.reply(200, self.public(release))
        if match := re.fullmatch(r"/releases/assets/(\d+)", path):
            return 302, {"Location": f"https://release-assets.githubusercontent.com/assets/{match.group(1)}"}, b""
        if match := re.fullmatch(r"/actions/workflows/([a-z-]+\.yml)/runs", path):
            runs = self.listings.get((match.group(1), query["head_sha"]), [])
            return self.reply(200, {"total_count": len(runs), "workflow_runs": runs})
        if match := re.fullmatch(r"/actions/runs/(\d+)/attempts/(\d+)", path):
            record = self.runs.get((int(match.group(1)), int(match.group(2))))
            return self.reply(200, record) if record else self.reply(404, {"message": "Not Found"})
        if match := re.fullmatch(r"/actions/runs/(\d+)/attempts/(\d+)/jobs", path):
            jobs = self.jobs.get((int(match.group(1)), int(match.group(2))), [])
            return self.reply(200, {"total_count": len(jobs), "jobs": jobs})
        raise AssertionError(f"unmodelled request {method} {path}")


class TipPublicationTests(unittest.TestCase):
    """Drive admit, stage and publish end to end across runs."""

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        base = Path(self.scratch.name)
        self.root = base / "repo"
        self.root.mkdir()
        self.bin = base / "bin"
        self.bin.mkdir()
        cosign = self.bin / "cosign"
        cosign.write_text(FAKE_COSIGN, encoding="utf-8")
        cosign.chmod(cosign.stat().st_mode | stat.S_IXUSR)
        self.git("init", "-q")
        for key, value in (("maintenance.auto", "false"), ("gc.auto", "0"), ("core.autocrlf", "false"),
                           ("user.name", "Release Test"), ("user.email", "release@example.invalid")):
            self.git("config", "--local", key, value)
        self.git("branch", "-m", "main")
        (self.root / "VERSION").write_text("0.1.9\n", encoding="utf-8")
        (self.root / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        self.floor = self.commit("floor")
        self.tag("v0.1.93", self.floor)
        self.terminal = self.fragment(394, "terminal", "Terminal per-merge release.")
        self.tag("v0.1.94", self.terminal)
        for patcher in (mock.patch.object(C, "TAG_LEDGER_FLOOR_TAG", "v0.1.93"),
                        mock.patch.object(C, "TAG_LEDGER_FLOOR_SHA", self.floor),
                        mock.patch.object(E, "TERMINAL_V4_SOURCE", self.terminal)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.github = FakeGitHub(self.root)
        self.seed_terminal()
        self.run_ids = iter(range(700000, 800000))

    # -- fixture ----------------------------------------------------------------

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def commit(self, marker: str) -> str:
        path = self.root / "markers" / f"{re.sub(r'[^a-z0-9]+', '-', marker.lower())}.txt"
        path.parent.mkdir(exist_ok=True)
        path.write_text(marker + "\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-q", "-m", marker)
        return self.git("rev-parse", "HEAD")

    def fragment(self, issue: int, slug: str, text: str, category: str = "Fixed") -> str:
        path = self.root / "changelog.d" / f"{issue}-{slug}.md"
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"### {category}\n\n- {text}\n", encoding="utf-8", newline="\n")
        return self.commit(f"add {issue}")

    def tag(self, name: str, target: str) -> None:
        date = dt.datetime.fromisoformat(self.git("show", "-s", "--format=%cI", target))
        content = (f"object {target}\ntype commit\ntag {name}\n"
                   f"tagger {C.RELEASE_TAGGER_NAME} <{C.RELEASE_TAGGER_EMAIL}> "
                   f"{int(date.timestamp())} {date.strftime('%z')}\n\nPlatform release {name} from {target}")
        sha = subprocess.run(["git", "-C", str(self.root), "hash-object", "-t", "tag", "-w", "--stdin"],
                             check=True, input=content.encode(), stdout=subprocess.PIPE).stdout.decode().strip()
        self.git("update-ref", f"refs/tags/{name}", sha)

    def seed_terminal(self) -> None:
        """The last per-merge Release, exactly as the v4 publisher left it."""
        github = self.github
        main_run = github.green(self.terminal)
        publisher = github.new_id()
        github.runs[(publisher, 3)] = {
            "id": publisher, "run_attempt": 3, "name": "Platform release", "path": E.PUBLISHER_WORKFLOW,
            "event": "workflow_run", "status": "completed", "conclusion": "success", "head_branch": "main",
            "head_sha": self.terminal, "repository": github.repository(), "head_repository": github.repository()}
        release_id = github.next_id + 1
        identity = C.render_release_identity(
            self.root, self.terminal, "v0.1.94", expected_base_sha=self.floor, expected_base_tag="v0.1.93",
            tag_object_sha=self.git("rev-parse", "refs/tags/v0.1.94"), release_id=release_id,
            main_run_id=main_run, main_run_attempt=1, platform_run_id=publisher, platform_run_attempt=3,
            github_repository=REPOSITORY, github_repository_id=E.REPOSITORY_ID).encode()
        bundle = fake_bundle(identity, subject=SUBJECT, sha=self.terminal, trigger="workflow_run")
        release = github.seed_release("v0.1.94", self.terminal, "terminal notes",
                                      {"platform-release-identity.v4.json": identity,
                                       "platform-release-identity.v4.json.sigstore.json": bundle})
        self.assertEqual(release["id"], release_id)
        self.terminal_identity = identity

    # -- driving the entry point -------------------------------------------------

    def invoke(self, command: str, *, sha: str, event: str = "workflow_run", run: int, attempt: int = 1,
               plan: str | None = None, staged: str | None = None, extra: dict | None = None):
        outputs = Path(self.scratch.name) / f"output-{command}-{run}-{attempt}"
        outputs.write_text("", encoding="utf-8")
        event_path = Path(self.scratch.name) / "event.json"
        event_path.write_text(json.dumps({"repository": {"full_name": REPOSITORY}, "workflow_run": {
            "name": "Pull request", "event": "push", "status": "completed", "conclusion": "success",
            "head_branch": "main", "path": C.WORKFLOW_PATH, "head_repository": {"full_name": REPOSITORY},
            "head_sha": sha}}), encoding="utf-8")
        environment = {
            "GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(E.REPOSITORY_ID), "GITHUB_EVENT_NAME": event,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/platform-release.yml@refs/heads/main",
            "GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": sha, "GITHUB_RUN_ID": str(run),
            "GITHUB_RUN_ATTEMPT": str(attempt), "GITHUB_EVENT_PATH": str(event_path),
            "GITHUB_OUTPUT": str(outputs), "PLATFORM_RELEASE_TOKEN": "test-token",
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
        }
        if plan is not None:
            environment["RELEASE_PLAN"] = plan
        if staged is not None:
            environment["STAGED_RELEASE_ID"] = staged
        environment.update(extra or {})
        stdout = io.StringIO()
        previous = Path.cwd()
        os.chdir(self.root)
        try:
            with mock.patch.dict(os.environ, environment), contextlib.redirect_stdout(stdout):
                for name in (*TIP.AMBIENT, "GITHUB_STEP_SUMMARY", "RELEASE_PLAN", "STAGED_RELEASE_ID"):
                    if name not in environment:
                        os.environ.pop(name, None)
                code = TIP.main([command], transport=self.github, sleep=lambda seconds: None)
        finally:
            os.chdir(previous)
        values = dict(line.split("=", 1) for line in outputs.read_text().splitlines() if "=" in line)
        return code, values, stdout.getvalue()

    def cycle(self, sha: str, *, event: str = "workflow_run", evidence: str = "success"):
        """One complete workflow run: admit, then stage and publish as the jobs would."""
        run = next(self.run_ids)
        self.github.publisher_run(run, 1, sha, event)
        code, admitted, log = self.invoke("admit", sha=sha, event=event, run=run)
        self.assertEqual(code, 0, log)
        result = {"run": run, "admit": admitted, "log": log}
        if admitted.get("decision") == "publish":
            code, staged, log = self.invoke("stage", sha=sha, event=event, run=run, plan=admitted["plan"])
            result.update(stage_code=code, staged=staged, stage_log=log)
            self.github.finish_job(run, 1, E.EVIDENCE_JOB, evidence if code == 0 else "failure")
            if code == 0:
                code, _, log = self.invoke("publish", sha=sha, event=event, run=run, plan=admitted["plan"],
                                           staged=staged["release_id"])
                result.update(publish_code=code, publish_log=log)
        elif admitted.get("decision") == "finalize":
            code, _, log = self.invoke("publish", sha=sha, event=event, run=run, plan=admitted["plan"])
            result.update(publish_code=code, publish_log=log)
        return result

    def merge(self, *issues: int) -> str:
        head = ""
        for issue in issues:
            head = self.fragment(issue, f"change-{issue}", f"Change {issue}.")
        self.github.main = head
        return head

    def identity(self, tag: str) -> dict:
        release = self.github.published(tag)
        asset = next(a for a in release["assets"] if a["name"].endswith(".json") and "sigstore" not in a["name"])
        return json.loads(self.github.assets[asset["id"]])

    # -- the routine path ----------------------------------------------------------

    def test_merges_during_one_ci_window_publish_one_release_with_every_fragment(self):
        first = self.merge(395)
        tip = self.merge(396, 397)
        self.github.green(tip)
        self.assertNotEqual(first, tip)
        result = self.cycle(tip)
        self.assertEqual(result["admit"]["decision"], "publish", result["log"])
        self.assertEqual((result["stage_code"], result["publish_code"]), (0, 0),
                         result.get("stage_log", "") + result.get("publish_log", ""))
        release = self.github.published("v0.1.95")
        self.assertTrue(release["immutable"])
        self.assertEqual(release["target_commitish"], tip)
        identity = self.identity("v0.1.95")
        self.assertEqual([f["path"] for f in identity["changelog"]["fragments"]],
                         ["changelog.d/395-change-395.md", "changelog.d/396-change-396.md",
                          "changelog.d/397-change-397.md"])
        self.assertEqual(identity["platform_release"]["job"], "evidence")
        self.assertEqual(identity["predecessor"], {"tag": "v0.1.94", "peeled_commit": self.terminal})
        for path in ("395-change-395", "396-change-396", "397-change-397"):
            self.assertIn(f"`changelog.d/{path}.md`", release["body"])
        self.assertEqual(self.git("cat-file", "-t", "refs/tags/v0.1.95"), "tag")
        again = self.cycle(tip, event="schedule")
        self.assertEqual(again["admit"]["decision"], "none")
        self.assertIn("already releases the tip", again["log"])

    def test_an_older_trigger_is_superseded_and_writes_nothing(self):
        first = self.merge(395)
        self.merge(396)
        self.git("checkout", "-q", first)
        before = len(self.github.releases)
        result = self.cycle(first)
        self.assertEqual(result["admit"]["decision"], "none")
        self.assertIn("superseded by main", result["log"])
        self.assertEqual(len(self.github.releases), before)
        self.assertFalse(any(method != "GET" for method, _ in self.github.requests))

    def test_the_hourly_schedule_publishes_a_green_tip_no_trigger_reached(self):
        tip = self.merge(395)
        self.github.green(tip)
        result = self.cycle(tip, event="schedule")
        self.assertEqual((result["admit"]["decision"], result["publish_code"]), ("publish", 0))
        self.assertEqual(self.identity("v0.1.95")["platform_release"]["event"], "schedule")

    def test_consecutive_tip_releases_chain_on_their_v5_predecessor(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.assertEqual(self.cycle(tip)["publish_code"], 0)
        second = self.merge(396)
        self.github.green(second)
        result = self.cycle(second)
        self.assertEqual(result.get("publish_code"), 0, result["log"] + result.get("stage_log", ""))
        self.assertEqual(self.identity("v0.1.96")["predecessor"]["tag"], "v0.1.95")
        self.assertEqual([f["path"] for f in self.identity("v0.1.96")["changelog"]["fragments"]],
                         ["changelog.d/396-change-396.md"])

    # -- CI admission -------------------------------------------------------------------

    def test_pending_and_red_ci_publish_nothing(self):
        tip = self.merge(395)
        cases = (
            ("no CI run", {}, "ci-pending"),
            ("main running", {"main_status": "in_progress"}, "ci-pending"),
            ("main failed", {"main_conclusion": "failure"}, "ci-red"),
            ("CodeQL running", {"codeql_status": "in_progress"}, "ci-pending"),
            ("CodeQL failed", {"codeql_conclusion": "failure"}, "ci-red"),
            ("CodeQL absent", {"codeql_conclusion": None}, "ci-pending"),
        )
        for label, options, reason in cases:
            with self.subTest(label):
                self.github.listings.clear()
                if label != "no CI run":
                    self.github.green(tip, **options)
                result = self.cycle(tip)
                self.assertEqual(result["admit"]["decision"], "none", result["log"])
                self.assertIn(reason, result["log"])
                self.assertIsNone(self.github.published("v0.1.95"))

    # -- predecessor integrity -------------------------------------------------------------

    def tamper_terminal(self, *, identity: bytes | None = None, bundle: bytes | None = None) -> None:
        release = self.github.published("v0.1.94")
        for asset in release["assets"]:
            payload = bundle if asset["name"].endswith("sigstore.json") else identity
            if payload is not None:
                self.github.assets[asset["id"]] = payload
                asset.update(size=len(payload), digest="sha256:" + hashlib.sha256(payload).hexdigest())

    def test_a_foreign_predecessor_refuses_before_any_write(self):
        tip = self.merge(395)
        self.github.green(tip)
        altered = self.terminal_identity.replace(b'"run_attempt":3', b'"run_attempt":2')
        terminal = json.loads(self.terminal_identity)
        terminal["release"]["id"] += 1
        foreign_release = (json.dumps(terminal, sort_keys=True, separators=(",", ":")) + "\n").encode()
        cases = (
            ("altered identity bytes", {"identity": altered,
                                        "bundle": fake_bundle(altered, subject=SUBJECT, sha=self.terminal,
                                                              trigger="workflow_run")}),
            ("foreign signer subject", {"bundle": fake_bundle(self.terminal_identity, subject=SUBJECT + "x",
                                                              sha=self.terminal, trigger="workflow_run")}),
            ("foreign trigger", {"bundle": fake_bundle(self.terminal_identity, subject=SUBJECT,
                                                       sha=self.terminal, trigger="workflow_dispatch")}),
            ("foreign release id", {"identity": foreign_release,
                                    "bundle": fake_bundle(foreign_release, subject=SUBJECT, sha=self.terminal,
                                                          trigger="workflow_run")}),
        )
        release = self.github.published("v0.1.94")
        original_assets = dict(self.github.assets)
        original_records = [dict(asset) for asset in release["assets"]]
        for label, tamper in cases:
            with self.subTest(label):
                self.tamper_terminal(**tamper)
                run = next(self.run_ids)
                self.github.publisher_run(run, 1, tip, "workflow_run")
                code, admitted, log = self.invoke("admit", sha=tip, run=run)
                self.assertEqual(code, 1, log)
                self.assertIn("RELEASE_REFUSED", log)
                self.assertFalse(any(method != "GET" for method, _ in self.github.requests))
                self.github.assets = dict(original_assets)
                release["assets"] = [dict(asset) for asset in original_records]

    # -- the transaction boundary --------------------------------------------------------------

    def test_a_pre_commit_failure_is_discarded_and_the_next_run_publishes(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("POST", r"^/repos/snaraj/platform/git/refs$", "403")
        failed = self.cycle(tip)
        self.assertEqual((failed["stage_code"], failed["publish_code"]), (0, 1))
        self.assertIn("HTTP 403", failed["publish_log"])
        self.assertIsNone(self.github.ref_record("v0.1.95"))
        retry = self.cycle(tip, event="schedule")
        self.assertEqual(retry.get("publish_code"), 0, retry.get("stage_log", "") + retry.get("publish_log", ""))
        self.assertIn("RELEASE_DISCARD tag=v0.1.95", retry["stage_log"])
        self.assertEqual(len([r for r in self.github.releases.values() if r["tag_name"] == "v0.1.95"]), 1)
        self.assertEqual(self.identity("v0.1.95")["platform_release"]["run_id"], retry["run"])

    def test_a_failed_stage_leaves_nothing_the_next_run_trusts(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("POST", r"/releases/\d+/assets$", "500")
        failed = self.cycle(tip)
        self.assertEqual(failed["stage_code"], 1)
        self.assertIn("HTTP 500", failed["stage_log"])
        retry = self.cycle(tip)
        self.assertEqual(retry.get("publish_code"), 0)
        self.assertEqual(self.identity("v0.1.95")["platform_release"]["run_id"], retry["run"])

    def test_a_lost_flip_response_is_judged_by_readback(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("PATCH", r"/releases/\d+$", "drop")
        result = self.cycle(tip)
        self.assertEqual(result["publish_code"], 0, result["publish_log"])
        self.assertIn("RELEASE_FLIP_RESPONSE", result["publish_log"])
        self.assertTrue(self.github.published("v0.1.95")["immutable"])

    def test_a_committed_but_unflipped_release_is_finalized_without_resigning(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("PATCH", r"/releases/\d+$", "503")
        first = self.cycle(tip)
        self.assertEqual(first["publish_code"], 1)
        self.assertIsNotNone(self.github.ref_record("v0.1.95"))
        self.assertIsNone(self.github.published("v0.1.95"))
        second = self.cycle(tip, event="schedule")
        self.assertEqual(second["admit"]["decision"], "finalize", second["log"])
        self.assertEqual(second["publish_code"], 0, second["publish_log"])
        # The Release still names the first run's evidence job: nothing re-signed.
        self.assertEqual(self.identity("v0.1.95")["platform_release"]["run_id"], first["run"])
        self.assertIn("mode=finalize", second["publish_log"])

    def test_a_failure_after_the_flip_never_strands_the_release(self):
        tip = self.merge(395)
        self.github.green(tip)
        # The post-flip proof fails: the publish job (and the run) end red.
        self.github.fault("GET", r"/releases/tags/v0\.1\.95$", "500")
        self.github.fault("GET", r"/releases/tags/v0\.1\.95$", "500")
        self.github.fault("GET", r"/releases/tags/v0\.1\.95$", "500")
        self.github.fault("GET", r"/releases/tags/v0\.1\.95$", "500")
        self.github.fault("GET", r"/releases/tags/v0\.1\.95$", "500")
        first = self.cycle(tip)
        self.assertEqual(first["publish_code"], 1)
        self.assertTrue(self.github.published("v0.1.95")["immutable"])
        self.github.runs[(first["run"], 1)].update(status="completed", conclusion="failure")
        # The next run proves it from the evidence job alone and moves on.
        after = self.cycle(tip, event="schedule")
        self.assertEqual(after["admit"]["decision"], "none", after["log"])
        self.assertIn("already releases the tip", after["log"])

    def test_finalize_refuses_evidence_from_a_failed_or_substituted_attempt(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("PATCH", r"/releases/\d+$", "503")
        first = self.cycle(tip)
        self.assertEqual(first["publish_code"], 1)
        # The signed attempt's evidence job is recorded as failed; a later
        # successful attempt of the same run must not stand in for it.
        self.github.finish_job(first["run"], 1, E.EVIDENCE_JOB, "failure")
        self.github.publisher_run(first["run"], 2, tip, "workflow_run")
        self.github.finish_job(first["run"], 2, E.EVIDENCE_JOB, "success")
        second = self.cycle(tip, event="schedule")
        self.assertEqual(second["admit"]["decision"], "finalize")
        self.assertEqual(second["publish_code"], 1)
        self.assertIn("evidence job is completed/failure", second["publish_log"])
        self.assertIsNone(self.github.published("v0.1.95"))

    def test_a_foreign_draft_for_the_next_tag_refuses_and_is_not_deleted(self):
        tip = self.merge(395)
        self.github.green(tip)
        foreign = self.github.seed_release("v0.1.95", tip, "foreign", {})
        foreign.update(draft=True, immutable=False, author={"login": "someone", "id": 7})
        result = self.cycle(tip)
        self.assertEqual(result["stage_code"], 1)
        self.assertIn("foreign draft", result["stage_log"])
        self.assertIn(foreign["id"], self.github.releases)
        self.assertFalse(any(path.endswith("/git/tags") for method, path in self.github.requests
                             if method == "POST"))

    def test_stage_refuses_when_main_advanced_after_admission(self):
        tip = self.merge(395)
        self.github.green(tip)
        run = next(self.run_ids)
        self.github.publisher_run(run, 1, tip, "workflow_run")
        code, admitted, log = self.invoke("admit", sha=tip, run=run)
        self.assertEqual(admitted["decision"], "publish", log)
        self.merge(396)
        # The evidence job's checkout stays at the tip that triggered the run.
        self.git("checkout", "-q", tip)
        code, _, log = self.invoke("stage", sha=tip, run=run, plan=admitted["plan"])
        self.assertEqual(code, 1)
        self.assertIn("main advanced before staging", log)
        self.assertFalse(any(method != "GET" for method, _ in self.github.requests))

    def test_publish_commits_only_its_own_runs_staged_evidence(self):
        tip = self.merge(395)
        self.github.green(tip)
        run = next(self.run_ids)
        self.github.publisher_run(run, 1, tip, "workflow_run")
        _, admitted, _ = self.invoke("admit", sha=tip, run=run)
        code, staged, log = self.invoke("stage", sha=tip, run=run, plan=admitted["plan"])
        self.assertEqual(code, 0, log)
        self.github.finish_job(run, 1, E.EVIDENCE_JOB, "success")
        other = next(self.run_ids)
        self.github.publisher_run(other, 1, tip, "workflow_run")
        foreign_plan = admitted["plan"].replace(f'"run_id":{run}', f'"run_id":{other}')
        code, _, log = self.invoke("publish", sha=tip, run=other, plan=foreign_plan, staged=staged["release_id"])
        self.assertEqual(code, 1)
        self.assertIn("publish commits only its own run's evidence", log)
        code, _, log = self.invoke("publish", sha=tip, run=run, plan=foreign_plan, staged=staged["release_id"])
        self.assertEqual(code, 1)
        self.assertIn("another run or attempt", log)
        self.assertIsNone(self.github.ref_record("v0.1.95"))

    # -- context and credentials -----------------------------------------------------------------

    def test_foreign_context_and_ambient_credentials_refuse(self):
        tip = self.merge(395)
        self.github.green(tip)
        for label, extra in (
            ("dispatch", {"GITHUB_EVENT_NAME": "workflow_dispatch"}),
            ("branch", {"GITHUB_REF": "refs/heads/feature"}),
            ("workflow", {"GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/other.yml@refs/heads/main"}),
            ("workflow sha", {"GITHUB_WORKFLOW_SHA": self.terminal}),
            ("ambient token", {"GH_TOKEN": "leaked"}),
            ("repository object", {"GITHUB_REPOSITORY_ID": "1"}),
        ):
            with self.subTest(label):
                code, _, log = self.invoke("admit", sha=tip, run=1, extra=extra)
                self.assertEqual(code, 1)
                self.assertIn("RELEASE_REFUSED", log)
        self.assertEqual(self.github.requests, [])

    def test_request_budgets_bound_the_longest_measured_paths(self):
        tip = self.merge(395, 396)
        self.github.green(tip)
        # The longest stage path discards the most leftovers it tolerates; the
        # longest publish path re-reads a lost flip.
        for _ in range(TIP.MAX_DISCARDS):
            leftover = self.github.seed_release("v0.1.95", tip, "leftover", {})
            leftover.update(draft=True, immutable=False)
        self.github.fault("PATCH", r"/releases/\d+$", "drop")
        result = self.cycle(tip)
        self.assertEqual(result["publish_code"], 0, result["stage_log"] + result["publish_log"])
        logs = result["log"] + result["stage_log"] + result["publish_log"]
        measured = {}
        for command in ("admit", "stage", "publish"):
            line = re.search(rf"RELEASE_SUMMARY command={command} outcome=\S+ requests=(\d+)/(\d+)", logs)
            measured[command] = (int(line.group(1)), int(line.group(2)))
        self.assertIn(f"RELEASE_DISCARD tag=v0.1.95", result["stage_log"])
        # Reads this fixture cannot exercise: CodeQL polls and further Release pages.
        unexercised = {"admit": TIP.CODEQL_READS * (TIP.CODEQL_POLLS - 1),
                       "stage": TIP.RELEASE_PAGES - 1, "publish": TIP.RELEASE_PAGES}
        for command, (used, budget) in measured.items():
            with self.subTest(command):
                self.assertLessEqual(used + unexercised[command], budget)
                self.assertLessEqual(budget, 2 * (used + unexercised[command]))

    # -- guards the mutation matrix names ------------------------------------------

    def stage_only(self, tip: str):
        run = next(self.run_ids)
        self.github.publisher_run(run, 1, tip, "workflow_run")
        _, admitted, log = self.invoke("admit", sha=tip, run=run)
        self.assertEqual(admitted.get("decision"), "publish", log)
        code, staged, log = self.invoke("stage", sha=tip, run=run, plan=admitted["plan"])
        self.assertEqual(code, 0, log)
        self.github.finish_job(run, 1, E.EVIDENCE_JOB, "success")
        return run, admitted["plan"], staged["release_id"]

    def restage_identity(self, release_id: str, tip: str, change) -> None:
        """Replace the staged identity with a correctly signed but altered one."""
        release = self.github.releases[int(release_id)]
        records = {asset["name"]: asset for asset in release["assets"]}
        identity_record = records["platform-release-identity.v5.json"]
        bundle_record = records["platform-release-identity.v5.json.sigstore.json"]
        value = json.loads(self.github.assets[identity_record["id"]])
        change(value)
        identity = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        bundle = fake_bundle(identity, subject=SUBJECT, sha=tip, trigger="workflow_run")
        for record, payload in ((identity_record, identity), (bundle_record, bundle)):
            self.github.assets[record["id"]] = payload
            record.update(size=len(payload), digest="sha256:" + hashlib.sha256(payload).hexdigest())

    def test_finalize_does_not_wait_for_a_newer_tip(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.fault("PATCH", r"/releases/\d+$", "503")
        self.assertEqual(self.cycle(tip)["publish_code"], 1)
        newer = self.merge(396)
        self.github.green(newer, main_conclusion="failure")
        result = self.cycle(newer, event="schedule")
        self.assertEqual(result["admit"]["decision"], "finalize", result["log"])
        self.assertEqual(result["publish_code"], 0, result["publish_log"])
        self.assertTrue(self.github.published("v0.1.95")["immutable"])

    def test_a_signed_identity_that_differs_from_the_derivation_is_never_committed(self):
        tip = self.merge(395, 396)
        self.github.green(tip)
        cases = (
            ("omitted fragment", lambda value: value["changelog"]["fragments"].pop()),
            ("foreign tag object", lambda value: value["tag"].update(
                object_sha=self.git("rev-parse", "refs/tags/v0.1.94"))),
        )
        for label, change in cases:
            with self.subTest(label):
                run, plan, release_id = self.stage_only(tip)
                self.restage_identity(release_id, tip, change)
                before = len(self.github.requests)
                code, _, log = self.invoke("publish", sha=tip, run=run, plan=plan, staged=release_id)
                self.assertEqual(code, 1, log)
                self.assertIn("RELEASE_REFUSED", log)
                self.assertFalse(any(method == "POST" and path.endswith("/git/refs")
                                     for method, path in self.github.requests[before:]))
                self.assertIsNone(self.github.ref_record("v0.1.95"))

    def test_a_release_that_reads_back_inexact_after_the_flip_is_refused(self):
        tip = self.merge(395)
        self.github.green(tip)
        self.github.on_publish = lambda release: release.update(body=release["body"] + "tampered\n")
        result = self.cycle(tip)
        self.assertEqual(result["publish_code"], 1)
        self.assertIn("Release notes are not exact", result["publish_log"])

    def test_stage_never_discards_behind_a_committed_tag(self):
        tip = self.merge(395)
        self.github.green(tip)
        run, plan, release_id = self.stage_only(tip)
        self.github.fault("PATCH", r"/releases/\d+$", "503")
        code, _, _ = self.invoke("publish", sha=tip, run=run, plan=plan, staged=release_id)
        self.assertEqual(code, 1)
        code, _, log = self.invoke("stage", sha=tip, run=run, plan=plan)
        self.assertEqual(code, 1)
        self.assertIn("the ledger moved since admission", log)
        self.assertIn(int(release_id), self.github.releases)

    def test_more_leftover_drafts_than_the_bound_refuse(self):
        tip = self.merge(395)
        self.github.green(tip)
        for _ in range(TIP.MAX_DISCARDS + 1):
            self.github.seed_release("v0.1.95", tip, "leftover", {}).update(draft=True, immutable=False)
        result = self.cycle(tip)
        self.assertEqual(result["stage_code"], 1)
        self.assertIn("refusing to guess", result["stage_log"])
        self.assertFalse(any(method == "DELETE" for method, _ in self.github.requests))

    def test_the_request_budget_is_a_hard_cap(self):
        calls = []
        api = TIP.Api("test-token", 2, transport=lambda *a: calls.append(a) or (200, {}, b"{}"))
        api.json("GET", "")
        api.json("GET", "")
        with self.assertRaisesRegex(TIP.Refusal, "budget 2 exhausted"):
            api.json("GET", "")
        self.assertEqual(len(calls), 2)

    def test_a_missing_or_foreign_terminal_checkpoint_refuses(self):
        tip = self.merge(395)
        self.github.green(tip)
        with mock.patch.object(E, "TERMINAL_V4_SOURCE", "c" * 40):
            result = self.invoke("admit", sha=tip, run=next(self.run_ids))
        self.assertEqual(result[0], 1)
        self.assertIn("only the terminal v4 checkpoint", result[2])
        release = self.github.published("v0.1.94")
        del self.github.releases[release["id"]]
        code, _, log = self.invoke("admit", sha=tip, run=next(self.run_ids))
        self.assertEqual(code, 1)
        self.assertIn("v0.1.94 has no published Release", log)


class TipLedgerAndContentTests(unittest.TestCase):
    """The ledger epoch rule and the canonical content binding."""

    def fixture(self) -> TipPublicationTests:
        case = TipPublicationTests("test_merges_during_one_ci_window_publish_one_release_with_every_fragment")
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_tip_releases_bind_one_or_more_fragments_and_never_zero(self):
        case = self.fixture()
        tip = case.merge(395, 396)
        case.tag("v0.1.95", tip)
        self.assertEqual(C._platform_tag_boundaries(case.root)[-1].tag, "v0.1.95")
        empty = case.commit("no fragment")
        case.tag("v0.1.96", empty)
        with self.assertRaisesRegex(C.ContractError, "at least one fragment"):
            C._platform_tag_boundaries(case.root)

    def test_per_merge_releases_still_bind_exactly_one_fragment(self):
        case = self.fixture()
        with mock.patch.object(E, "TERMINAL_V4_TAG", "v0.1.95"):
            tip = case.merge(395, 396)
            case.tag("v0.1.95", tip)
            with self.assertRaisesRegex(C.ContractError, "exactly one fragment"):
                C._platform_tag_boundaries(case.root)

    def test_identity_binds_every_fragment_byte(self):
        case = self.fixture()
        tip = case.merge(395, 396)
        case.github.green(tip)
        self.assertEqual(case.cycle(tip)["publish_code"], 0)
        identity = case.identity("v0.1.95")
        for fragment in identity["changelog"]["fragments"]:
            payload = (case.root / fragment["path"]).read_bytes()
            self.assertEqual(fragment["sha256"], "sha256:" + hashlib.sha256(payload).hexdigest())
        bound = TIP.fragments(case.root, case.terminal, tip)
        kwargs = dict(tag="v0.1.95", source=tip, base_tag="v0.1.94", base_sha=case.terminal,
                      tag_object_sha=identity["tag"]["object_sha"], release_id=identity["release"]["id"],
                      main_run=(identity["main_ci"]["run_id"], 1),
                      platform_run=(identity["platform_release"]["run_id"], 1), event="workflow_run")
        exact = TIP.render_identity(case.root, bound=bound, **kwargs)
        for label, mutated in (("omitted", bound[:1]), ("duplicated", bound + bound[:1]),
                               ("altered", ((bound[0][0], "0" * 64),) + bound[1:]),
                               ("reordered", tuple(reversed(bound)))):
            with self.subTest(label):
                self.assertNotEqual(TIP.render_identity(case.root, bound=mutated, **kwargs), exact)

    def test_notes_fall_back_to_digests_past_the_body_budget(self):
        case = self.fixture()
        tip = case.merge(395, 396)
        bound = TIP.fragments(case.root, case.terminal, tip)
        full = TIP.render_notes(case.root, "v0.1.95", tip, "v0.1.94", bound)
        self.assertIn("- Change 395.", full)
        with mock.patch.object(TIP, "NOTES_BUDGET_BYTES", 200):
            compact = TIP.render_notes(case.root, "v0.1.95", tip, "v0.1.94", bound)
        self.assertNotIn("- Change 395.", compact)
        for path, digest in bound:
            self.assertIn(f"`{path}` (`sha256:{digest}`)", compact)

    def test_asset_redirects_never_carry_the_credential_or_leave_github(self):
        api = TIP.Api("test-token", 5, transport=lambda *a: (302, {"Location": "https://evil.example/x"}, b""))
        with self.assertRaisesRegex(TIP.Refusal, "redirect is foreign"):
            api.asset(1, 10)


if __name__ == "__main__":
    unittest.main()
