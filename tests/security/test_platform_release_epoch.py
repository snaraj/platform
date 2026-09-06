"""Offline policy and shell checks for the single repository name transition.

Synthetic Sigstore bytes here exercise structural/hash binding only. Hosted
signing and post-rename certificate verification remain rollout evidence.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from . import test_platform_release_identity_asset as legacy
from .support import load_script

CONTRACT = legacy.MODULE
FIXTURE = legacy.PlatformReleaseIdentityAssetTests()

ROOT = Path(__file__).resolve().parents[2]
EPOCH = CONTRACT.EPOCH
OLD = "snaraj/website-infrastructure"
NEW = "snaraj/platform"
OBJECT_ID = 1327645656
CHECKPOINT = "b4bf0ac19038b1bca43651b601a348f8a84e7163"
SELECTOR = "sha256:c104c4b87f9932f08302fd30454605b3326794097cfbe5d4060db8f9cca5c003"
BUILD = "ce8598a9f0b4eca52cff231ed94137926df13c08"


def evidence(tag):
    value = FIXTURE.evidence()
    epoch = 1 if tag in ("v0.1.68", "v0.1.69") else 2
    value["repository"] = OLD if epoch == 1 else NEW
    value["schema"] = f"https://snaraj.dev/schemas/platform-release-identity/v{epoch}"
    if epoch == 2:
        value["repository_id"] = OBJECT_ID
    value["tag"]["name"] = tag
    value["release"]["tag_name"] = tag
    value["predecessor"] = {"tag": "v0.1." + str(int(tag.rsplit(".", 1)[1]) - 1),
                            "peeled_commit": CHECKPOINT if tag == "v0.1.69" else FIXTURE.PREDECESSOR}
    value["selector"]["digest"] = SELECTOR
    value["selector"]["provenance"]["subject_digest"] = SELECTOR
    value["selector"]["provenance"]["source_sha"] = BUILD
    return value


def records(value, transport=NEW):
    identity = FIXTURE.canonical(value)
    bundle = FIXTURE.bundle(identity)
    record = FIXTURE.release(identity, bundle)
    tag = value["tag"]["name"]
    record["tag_name"] = tag
    record["name"] = f"Platform {tag}"
    for asset in record["assets"]:
        if value["schema"].endswith("/v2"):
            asset["name"] = asset["name"].replace(".v1.", ".v2.")
        asset["url"] = f"https://api.github.com/repos/{transport}/releases/assets/{asset['id']}"
        asset["browser_download_url"] = f"https://github.com/{transport}/releases/download/{tag}/{asset['name']}"
    return identity, bundle, record


def validate(value, transport=NEW, object_id=OBJECT_ID):
    identity, bundle, record = records(value, transport)
    return CONTRACT.selector_image_from_release(
        record, identity=identity, bundle=bundle,
        expected_tag=value["tag"]["name"], expected_sha=FIXTURE.SOURCE,
        expected_selector_build_sha=BUILD, expected_tag_object_sha=FIXTURE.TAG_OBJECT,
        expected_tree_sha=FIXTURE.TREE, api_repository=transport, api_repository_id=object_id,
    )


class PlatformReleaseEpochTests(unittest.TestCase):
    def test_git_remotes_require_exact_urls_and_original_object(self):
        for name in (OLD, NEW):
            for url in (f"https://github.com/{name}.git", "git" + "@" + f"github.com:{name}.git"):
                result = subprocess.CompletedProcess([], 0, json.dumps({"id": OBJECT_ID, "full_name": name}), "")
                with self.subTest(url=url), mock.patch.object(EPOCH.subprocess, "run", return_value=result) as run:
                    self.assertEqual(EPOCH.git_remote(url), name)
                    run.assert_called_once_with(
                        ["gh", "api", "--hostname", "github.com", "--method", "GET", f"repos/{name}", "--jq", "{id, full_name}"],
                        capture_output=True, text=True, check=True, timeout=15,
                    )
        for url in ("https://github.com/other/platform.git", "https://example.invalid/snaraj/platform.git",
                    "https://github.com/snaraj/platform", "https://github.com/snaraj/platform.git/",
                    "https://github.com/snaraj/Platform.git", "https://github.com/snaraj/platform.git?x=1",
                    "ssh://git" + "@" + "github.com/snaraj/platform.git"):
            result = subprocess.CompletedProcess([], 0, json.dumps({"id": OBJECT_ID, "full_name": NEW}), "")
            with self.subTest(url=url), mock.patch.object(EPOCH.subprocess, "run", return_value=result) as run, self.assertRaises(ValueError):
                EPOCH.git_remote(url)
            run.assert_not_called()
        for record in ({}, [], {"id": OBJECT_ID + 1, "full_name": NEW},
                       {"id": OBJECT_ID, "full_name": OLD}, {"id": str(OBJECT_ID), "full_name": NEW},
                       {"id": float(OBJECT_ID), "full_name": NEW}):
            result = subprocess.CompletedProcess([], 0, json.dumps(record), "")
            with self.subTest(record=record), mock.patch.object(EPOCH.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                EPOCH.git_remote(f"https://github.com/{NEW}.git")

    def test_git_remote_cli_is_separate_and_lookup_failure_is_closed(self):
        url = f"https://github.com/{NEW}.git"
        argv = ["epoch", "--git-remote", url]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(EPOCH, "git_remote", return_value=NEW) as remote, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(EPOCH.main(), 0)
        self.assertEqual(output.getvalue().strip(), NEW)
        remote.assert_called_once_with(url)
        with mock.patch.object(sys, "argv", argv + ["v0.1.70"]), mock.patch.object(EPOCH, "git_remote") as remote, redirect_stdout(io.StringIO()):
            self.assertEqual(EPOCH.main(), 1)
        remote.assert_not_called()
        for error in (subprocess.CalledProcessError(1, ["gh"], stderr="private diagnostic"),
                      subprocess.TimeoutExpired(["gh"], 15), OSError("unavailable")):
            with self.subTest(error=type(error).__name__), mock.patch.object(sys, "argv", argv), mock.patch.object(EPOCH.subprocess, "run", side_effect=error), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(EPOCH.main(), 1)
            self.assertNotIn("private diagnostic", output.getvalue())

    def test_closed_publication_edges_and_roots(self):
        self.assertEqual(EPOCH.CHECKPOINT_TAG, "v0.1.68")
        self.assertEqual(EPOCH.CHECKPOINT_SOURCE, CHECKPOINT)
        self.assertEqual(EPOCH.FROZEN_SELECTOR_DIGEST, SELECTOR)
        self.assertEqual(EPOCH.FROZEN_SELECTOR_SOURCE, BUILD)
        for name, tag, base, sha, expected_epoch in (
            (OLD, "v0.1.69", "v0.1.68", CHECKPOINT, 1),
            (NEW, "v0.1.70", "v0.1.69", FIXTURE.SOURCE, 2),
            (NEW, "v0.1.71", "v0.1.70", FIXTURE.SOURCE, 2),
        ):
            with self.subTest(tag=tag):
                policy = EPOCH.publication(name, OBJECT_ID, tag, base, sha)
                self.assertEqual(policy["version"], expected_epoch)
                self.assertEqual(policy["repository"], name)
                self.assertEqual(policy["asset"], f"platform-release-identity.v{expected_epoch}.json")
                self.assertEqual(policy["bundle"], policy["asset"] + ".sigstore.json")
                self.assertEqual(policy["subject"], f"https://github.com/{name}/.github/workflows/platform-release.yml@refs/heads/main")
                self.assertEqual(policy["selector_digest"], SELECTOR)
                self.assertEqual(policy["selector_source"], BUILD)
        for args in (
            (OLD, OBJECT_ID, "v0.1.68", "v0.1.67", FIXTURE.SOURCE),
            (OLD, OBJECT_ID, "v0.1.70", "v0.1.69", FIXTURE.SOURCE),
            (NEW, OBJECT_ID, "v0.1.69", "v0.1.68", CHECKPOINT),
            (NEW, OBJECT_ID, "v0.1.70", "v0.1.68", CHECKPOINT),
            (NEW, OBJECT_ID, "v0.1.72", "v0.1.70", FIXTURE.SOURCE),
            (OLD, OBJECT_ID, "v0.1.69", "v0.1.68", FIXTURE.SOURCE),
            (NEW, OBJECT_ID, "v0.1.70", "v0.1.69", "main"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                EPOCH.publication(*args)
        for name, object_id in ((NEW, OBJECT_ID + 1), (NEW, True), (NEW, float(OBJECT_ID)), (NEW, str(OBJECT_ID)),
                                (NEW, None), ("snaraj/platform-k8s-infra", OBJECT_ID),
                                ("snaraj/Platform", OBJECT_ID), ("other/platform", OBJECT_ID)):
            with self.subTest(name=name, object_id=object_id), self.assertRaises(ValueError):
                EPOCH.publication(name, object_id, "v0.1.70", "v0.1.69", FIXTURE.SOURCE)
        for tag in (None, "v01.1.70", "v0.1.70-rc.1", "v0.1.70\n", "v" + "1" * 70):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                EPOCH.identity(tag)

    def test_historical_bytes_and_v2_metadata_are_separate(self):
        for tag in ("v0.1.68", "v0.1.69", "v0.1.70", "v0.1.71"):
            value = evidence(tag)
            before = FIXTURE.canonical(value)
            self.assertEqual(validate(value), SELECTOR)
            self.assertEqual(FIXTURE.canonical(value), before)
        for tag in ("v0.1.68", "v0.1.69"):
            self.assertEqual(validate(evidence(tag), OLD), SELECTOR)
        with self.assertRaises(CONTRACT.ContractError):
            validate(evidence("v0.1.70"), OLD)
        with self.assertRaises(CONTRACT.ContractError):
            validate(evidence("v0.1.69"), NEW, OBJECT_ID + 1)
        with self.assertRaises(ValueError):
            EPOCH.metadata_repository("v0.1.70", None, None)
        self.assertEqual(EPOCH.metadata_repository("v0.1.41", None, None), OLD)
        for name, object_id in ((NEW, None), (None, OBJECT_ID)):
            with self.assertRaises(ValueError):
                EPOCH.metadata_repository("v0.1.41", name, object_id)

    def test_signed_epoch_mutations_fail_with_rehashed_structural_bundles(self):
        mutations = (
            ("v0.1.70", ("repository",), OLD),
            ("v0.1.70", ("repository_id",), OBJECT_ID + 1),
            ("v0.1.70", ("schema",), "https://snaraj.dev/schemas/platform-release-identity/v1"),
            ("v0.1.70", ("predecessor", "tag"), "v0.1.68"),
            ("v0.1.69", ("predecessor", "peeled_commit"), FIXTURE.SOURCE),
            ("v0.1.69", ("predecessor", "tag"), "v0.1.67"),
            ("v0.1.70", ("selector", "signature", "certificate_identity"), f"https://github.com/{NEW}/{EPOCH.WORKFLOW}"),
        )
        for tag, path, replacement in mutations:
            value = evidence(tag)
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path, tag=tag), self.assertRaises(CONTRACT.ContractError):
                validate(value)
            if path[0] != "selector":
                with self.assertRaises(ValueError):
                    EPOCH.validate_identity(value)
        for tag in ("v0.1.69", "v0.1.70"):
            value = evidence(tag)
            value["selector"]["digest"] = "sha256:" + "a" * 64
            value["selector"]["provenance"]["subject_digest"] = value["selector"]["digest"]
            with self.assertRaises(CONTRACT.ContractError):
                validate(value)
            value = evidence(tag)
            value["selector"]["provenance"]["source_sha"] = FIXTURE.SOURCE
            with self.assertRaises(ValueError):
                EPOCH.validate_identity(value)
        value = evidence("v0.1.69")
        value["repository_id"] = OBJECT_ID
        with self.assertRaises(CONTRACT.ContractError):
            validate(value)

    def test_run_metadata_alias_requires_the_original_object_and_exact_attempt(self):
        for tag in ("v0.1.69", "v0.1.70"):
            value = evidence(tag)
            runs = []
            for key in ("main_ci", "platform_release"):
                receipt = value[key]
                runs.append({"id": receipt["run_id"], "run_attempt": receipt["run_attempt"],
                             "event": receipt["event"], "head_branch": "main", "head_sha": FIXTURE.SOURCE,
                             "path": receipt["workflow"], "status": "completed", "conclusion": "success",
                             "repository": {"full_name": NEW, "id": OBJECT_ID}})
            CONTRACT.validate_identity_run_records(FIXTURE.canonical(value), *runs)
            for repository in ({}, {"full_name": NEW}, {"full_name": NEW, "id": OBJECT_ID + 1},
                               {"full_name": OLD, "id": OBJECT_ID} if tag.endswith("70") else {"full_name": OLD}):
                changed = copy.deepcopy(runs)
                changed[1]["repository"] = repository
                with self.subTest(tag=tag, repository=repository), self.assertRaises(CONTRACT.ContractError):
                    CONTRACT.validate_identity_run_records(FIXTURE.canonical(value), *changed)
            changed = copy.deepcopy(runs)
            changed[0]["run_attempt"] += 1
            with self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_identity_run_records(FIXTURE.canonical(value), *changed)

    def test_v1_schema_is_frozen_and_v2_pins_legacy_selector(self):
        folder = ROOT / "bootstrap/flux/release-selector"
        self.assertEqual(hashlib.sha256((folder / "platform-release-identity.v1.schema.json").read_bytes()).hexdigest(),
                         "2ed4c4460e0ba7870b357bb7489a40f44f3d3364355ac02f5ca5fc2de22987d7")
        schema = json.loads((folder / "platform-release-identity.v2.schema.json").read_bytes())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(evidence("v0.1.70")))
        self.assertEqual(schema["properties"]["repository"], {"const": NEW})
        self.assertEqual(schema["properties"]["repository_id"], {"const": OBJECT_ID})
        self.assertEqual(schema["properties"]["schema"]["const"], schema["$id"])
        self.assertEqual(schema["$id"], EPOCH.identity("v0.1.70")["schema"])
        selector = schema["properties"]["selector"]["properties"]
        self.assertEqual(selector["digest"], {"const": SELECTOR})
        self.assertEqual(selector["provenance"]["properties"]["source_sha"], {"const": BUILD})
        self.assertEqual(selector["provenance"]["properties"]["subject_digest"], {"const": SELECTOR})
        self.assertEqual(schema["$defs"]["workflowIdentity"]["const"], CONTRACT.SELECTOR_CERTIFICATE_SUBJECT)

    def test_cli_checks_live_metadata_context_and_frozen_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "repository.json"
            path.write_text(json.dumps({"full_name": OLD, "id": OBJECT_ID}))
            args = ["epoch", "v0.1.69", "--repository", OLD, "--repository-id", str(OBJECT_ID),
                    "--base-tag", "v0.1.68", "--base-sha", CHECKPOINT,
                    "--repository-json", str(path), "--source-sha", FIXTURE.SOURCE]
            for code in (0, 1, 128):
                with mock.patch.object(sys, "argv", args), mock.patch.object(EPOCH.subprocess, "run", return_value=subprocess.CompletedProcess([], code)) as run, redirect_stdout(io.StringIO()):
                    self.assertEqual(EPOCH.main(), 0 if code == 0 else 1)
                    self.assertEqual(run.call_args.args[0], ["git", "diff", "--exit-code", BUILD, FIXTURE.SOURCE, "--", "cmd/platform-release-selector", "internal/releaseselector", "go.mod"])
            with mock.patch.object(sys, "argv", args[:-1] + ["main"]), mock.patch.object(EPOCH.subprocess, "run") as run, redirect_stdout(io.StringIO()):
                self.assertEqual(EPOCH.main(), 1)
                run.assert_not_called()
            path.write_text(json.dumps({"full_name": NEW, "id": OBJECT_ID}))
            with mock.patch.object(sys, "argv", args), mock.patch.object(EPOCH.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(EPOCH.main(), 1)
                run.assert_not_called()
            for args in (["epoch", "v0.1.70"], ["epoch", "v0.1.70", "--repository", NEW],
                         ["epoch", "v0.1.70", "--source-sha", "main"]):
                with mock.patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
                    self.assertEqual(EPOCH.main(), 0 if len(args) == 2 else 1)

    def test_renderer_and_cli_bind_the_new_identity_and_transport(self):
        for tag, name in (("v0.1.69", OLD), ("v0.1.70", NEW)):
            expected = evidence(tag)
            base = expected["predecessor"]
            window = CONTRACT.TransitionWindow(
                base_sha=base["peeled_commit"], base_tag=base["tag"],
                intent=CONTRACT.Intent(FIXTURE.SOURCE, CONTRACT.Version(0, 1, int(tag.rsplit(".", 1)[1]))),
                fragment_path=expected["changelog"]["fragment_path"], fragment_sha256="e" * 64,
            )
            args = dict(expected_base_sha=base["peeled_commit"], expected_base_tag=base["tag"],
                        tag_object_sha=FIXTURE.TAG_OBJECT, release_id=FIXTURE.RELEASE_ID,
                        main_run_id=100, main_run_attempt=2, platform_run_id=200, platform_run_attempt=3,
                        selector_image_digest=SELECTOR, selector_build_sha=BUILD,
                        github_repository=name, github_repository_id=OBJECT_ID)
            with (mock.patch.object(CONTRACT, "_exact_commit", return_value=FIXTURE.SOURCE),
                  mock.patch.object(CONTRACT, "_git", return_value=FIXTURE.TREE),
                  mock.patch.object(CONTRACT, "discover_transition_window", return_value=window),
                  mock.patch.object(CONTRACT, "_file_bytes", return_value=FIXTURE.receipt_bytes())):
                self.assertEqual(CONTRACT.render_release_identity(ROOT, FIXTURE.SOURCE, tag, **args).encode(), FIXTURE.canonical(expected))
                with self.assertRaises(CONTRACT.ContractError):
                    CONTRACT.render_release_identity(ROOT, FIXTURE.SOURCE, tag, **{**args, "github_repository_id": OBJECT_ID + 1})
            identity, bundle, record = records(expected, name)
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                (folder / "identity").write_bytes(identity)
                (folder / "bundle").write_bytes(bundle)
                (folder / "release").write_text(json.dumps(record))
                common = ["--identity", str(folder / "identity"), "--bundle", str(folder / "bundle"),
                          "--release-json", str(folder / "release"), "--tag", tag, "--source-sha", FIXTURE.SOURCE,
                          "--selector-build-sha", BUILD, "--tag-object-sha", FIXTURE.TAG_OBJECT,
                          "--source-tree-sha", FIXTURE.TREE, "--api-repository", name, "--api-repository-id", str(OBJECT_ID)]
                for command in ("identity-release-record", "selector-image-from-release", "identity-release-state"):
                    extra = ["--http-status", "200", "--require", "exact"] if command.endswith("state") else []
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(CONTRACT.main([command, *common, *extra]), 0)

    def test_local_delivery_cli_requires_original_object_before_acting(self):
        promoter = load_script("promote_releases.py")
        ready = promoter.READY
        for name in (OLD, NEW):
            ready.verify_repository(name, {"full_name": name, "id": OBJECT_ID})
        for record in ({"full_name": NEW, "id": OBJECT_ID + 1}, {"full_name": NEW},
                       {"full_name": OLD, "id": OBJECT_ID}):
            with self.assertRaises(ready.Refusal):
                ready.verify_repository(NEW, record)
        for object_id in (OBJECT_ID, OBJECT_ID + 1):
            with (mock.patch.object(promoter.GitHub, "api", return_value={"full_name": NEW, "id": object_id}) as api,
                  mock.patch.object(promoter, "tick", return_value=0) as tick):
                result = promoter.main(["--github-repository", NEW, "tick", "--repo", str(ROOT), "--dry-run"])
                self.assertEqual(result, 0 if object_id == OBJECT_ID else 1)
                self.assertEqual(tick.call_count, 1 if object_id == OBJECT_ID else 0)
                api.assert_called_once_with(f"repos/{NEW}")
        self.assertEqual(promoter.REPOSITORY, OLD)
        snapshot = {"head": FIXTURE.SOURCE, "draft": True, "behind_by": 0, "state": "open",
                    "baseRef": "main", "defaultBranch": "main", "body": "", "labels": [], "checks": [], "comments": []}
        for object_id in (OBJECT_ID, OBJECT_ID + 1):
            with (mock.patch.object(ready, "gh", return_value={"full_name": NEW, "id": object_id}) as query,
                  mock.patch.object(ready, "snapshot", return_value=snapshot) as capture,
                  mock.patch.object(ready, "ready_decision", return_value=([], [], [])), redirect_stdout(io.StringIO())):
                self.assertEqual(ready.main(["11", "--repo", NEW, "--json"]), 0 if object_id == OBJECT_ID else 1)
                self.assertEqual(capture.call_count, 1 if object_id == OBJECT_ID else 0)
                query.assert_called_once_with(f"repos/{NEW}")
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(promoter.main(["--github-repository", NEW, "launchd-plist", "--repo", "checkout", "--log", "output"]), 0)
        self.assertIn("<string>--github-repository</string><string>snaraj/platform</string>", output.getvalue())

    def test_current_release_rerun_checks_signature_and_previous_attempt_in_condition(self):
        script = (ROOT / "scripts/ci/publish-platform-release.sh").read_text()
        functions = []
        for name, next_name in (("download_identity_asset", "verify_identity_signature"),
                                ("verify_identity_signature", "download_identity_pair"),
                                ("download_identity_pair", "upload_identity_asset"),
                                ("validate_identity_runs", "validate_selector_transition"),
                                ("classify_current_release", "classify_predecessor_release")):
            functions.append(script.split(name + "() {", 1)[1].split("\n" + next_name + "()", 1)[0])
            functions[-1] = name + "() {" + functions[-1]
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fake = folder / "cosign"
            fake.write_text('#!/bin/sh\nexit "$SIGNATURE_RESULT"\n')
            fake.chmod(0o700)
            value = evidence("v0.1.70")
            identity, bundle, record = records(value)
            (folder / "identity.input").write_bytes(identity)
            (folder / "bundle.input").write_bytes(bundle)
            (folder / "ref").write_text(json.dumps({"object": {"sha": FIXTURE.TAG_OBJECT}}))
            runs = []
            for key in ("main_ci", "platform_release"):
                receipt = value[key]
                runs.append({"id": receipt["run_id"], "run_attempt": receipt["run_attempt"],
                             "event": receipt["event"], "head_branch": "main", "head_sha": FIXTURE.SOURCE,
                             "path": receipt["workflow"], "status": "completed", "conclusion": "success",
                             "repository": {"full_name": NEW, "id": OBJECT_ID}})
            prelude = r'''
set -euo pipefail
contract=scripts/ci/platform_release_contract.py
epoch_contract=scripts/ci/platform_release_epoch.py
api="https://api.github.com/repos/${GITHUB_REPOSITORY}"
api_version=2026-03-10
identity_issuer=https://token.actions.githubusercontent.com
write_token=synthetic-job-token
release_json="${RUNNER_TEMP}/release.output"
identity_download="${RUNNER_TEMP}/identity.output"
bundle_download="${RUNNER_TEMP}/bundle.output"
ref_json="${RUNNER_TEMP}/ref"
legacy_main_run_json="${RUNNER_TEMP}/main.output"
legacy_platform_run_json="${RUNNER_TEMP}/platform.output"
transport_args=(--api-repository "${GITHUB_REPOSITORY}" --api-repository-id "${GITHUB_REPOSITORY_ID}")
get_json() { cp "${RUNNER_TEMP}/release.input" "$3"; printf '200'; }
get_public_json() {
  case "$1" in
    */actions/runs/100/attempts/2) cp "${RUNNER_TEMP}/main.input" "$2" ;;
    */actions/runs/200/attempts/3) cp "${RUNNER_TEMP}/platform.input" "$2" ;;
    *) return 1 ;;
  esac
  printf '200'
}
git() { test "$1" = rev-parse; printf '%s\n' "${SOURCE_TREE}"; }
curl() {
  local output='' url=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) output="$2"; shift 2 ;;
      https:*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  case "${url}" in
    "${api}/releases/assets/900") cp "${RUNNER_TEMP}/identity.input" "${output}" ;;
    "${api}/releases/assets/901") cp "${RUNNER_TEMP}/bundle.input" "${output}" ;;
    *) return 1 ;;
  esac
  printf '200'
}
'''
            command = prelude + "\n".join(functions) + "\nif classify_current_release exact; then exit 0; else exit 1; fi\n"
            environment = {**os.environ, "PATH": temporary + os.pathsep + os.environ["PATH"],
                           "RUNNER_TEMP": temporary, "GITHUB_REPOSITORY": NEW, "GITHUB_REPOSITORY_ID": str(OBJECT_ID),
                           "SOURCE_SHA": FIXTURE.SOURCE, "SOURCE_TREE": FIXTURE.TREE, "TAG": "v0.1.70",
                           "SELECTOR_IMAGE_DIGEST": SELECTOR, "SELECTOR_BUILD_SHA": BUILD,
                           "GITHUB_RUN_ID": "201", "GITHUB_RUN_ATTEMPT": "1", "MAIN_RUN_ID": "100", "MAIN_RUN_ATTEMPT": "2",
                           "SIGNATURE_RESULT": "0"}
            for case in ("previous-success", "own-current", "bad-signature", "failed-previous", "foreign-object", "wrong-main", "wrong-selector"):
                selected = {**environment}
                current_runs = copy.deepcopy(runs)
                if case == "own-current" or case == "wrong-main":
                    selected.update(GITHUB_RUN_ID="200", GITHUB_RUN_ATTEMPT="3")
                if case == "bad-signature":
                    selected["SIGNATURE_RESULT"] = "1"
                if case == "failed-previous":
                    current_runs[1]["conclusion"] = "failure"
                if case == "foreign-object":
                    current_runs[1]["repository"]["id"] += 1
                if case == "wrong-main":
                    selected["MAIN_RUN_ATTEMPT"] = "3"
                if case == "wrong-selector":
                    selected["SELECTOR_IMAGE_DIGEST"] = "sha256:" + "a" * 64
                (folder / "release.input").write_text(json.dumps(record))
                (folder / "main.input").write_text(json.dumps(current_runs[0]))
                (folder / "platform.input").write_text(json.dumps(current_runs[1]))
                result = subprocess.run(["bash", "-c", command], cwd=ROOT, env=selected, capture_output=True, text=True)
                with self.subTest(case=case):
                    self.assertEqual(result.returncode, 0 if case in ("previous-success", "own-current") else 1, result.stderr)

    def test_shell_signature_uses_external_tag_root_and_propagates_failure(self):
        script = (ROOT / "scripts/ci/publish-platform-release.sh").read_text()
        function = script.split("verify_identity_signature() {", 1)[1].split("\ndownload_identity_pair()", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "cosign"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CALLS"\nexit "$RESULT"\n')
            fake.chmod(0o700)
            calls = Path(temporary) / "calls"
            for tag, name in (("v0.1.69", OLD), ("v0.1.70", NEW)):
                for code in (0, 1):
                    command = 'set -euo pipefail\nepoch_contract=scripts/ci/platform_release_epoch.py\nidentity_issuer=https://token.actions.githubusercontent.com\nverify_identity_signature() {' + function + '\nverify_identity_signature identity.json bundle.json "$TAG"\n'
                    result = subprocess.run(["bash", "-c", command], cwd=ROOT, env={**os.environ, "PATH": temporary + os.pathsep + os.environ["PATH"], "CALLS": str(calls), "RESULT": str(code), "TAG": tag}, capture_output=True, text=True)
                    self.assertEqual(result.returncode, code, result.stderr)
                    argv = calls.read_text().splitlines()
                    self.assertEqual(argv[argv.index("--certificate-identity") + 1], f"https://github.com/{name}/{EPOCH.WORKFLOW}")
                    self.assertEqual(argv[argv.index("--certificate-oidc-issuer") + 1], "https://token.actions.githubusercontent.com")


if __name__ == "__main__":
    unittest.main()
