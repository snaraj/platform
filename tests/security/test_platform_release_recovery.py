"""Offline policy controls for the finite historical-source recovery reader."""

import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from .support import load_script
from . import test_platform_release_contract as ci
from . import test_platform_release_v4 as v4

ROOT = Path(__file__).resolve().parents[2]
R = load_script("ci/platform_release_recovery.py", module_name="recovery_policy_tests")
SOURCE = "e" * 40
TREE = "f" * 40
REPOSITORY = {"id": 1327645656, "full_name": "snaraj/platform", "default_branch": "main"}


def environment():
    return {"GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "snaraj/platform",
            "GITHUB_REPOSITORY_ID": "1327645656", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": SOURCE,
            "GITHUB_WORKFLOW_SHA": SOURCE, "GITHUB_RUN_ID": "500",
            "GITHUB_WORKFLOW_REF": "snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main"}


def event():
    return {"repository": copy.deepcopy(REPOSITORY), "inputs": {}}


def bound():
    return R.context(environment(), event())


def run(run_id=500, attempt=1, source=SOURCE, tree=TREE, workflow="platform-release-recovery.yml"):
    dispatch = workflow == "platform-release-recovery.yml"
    return {"id": run_id, "run_attempt": attempt, "head_sha": source, "head_branch": "main",
            "head_commit": {"id": source, "tree_id": tree}, "repository": copy.deepcopy(REPOSITORY),
            "head_repository": copy.deepcopy(REPOSITORY), "path": ".github/workflows/" + workflow,
            "name": "CodeQL" if workflow == "codeql.yml" else "Pull request",
            "event": "workflow_dispatch" if dispatch else "push",
            "status": "in_progress" if dispatch else "completed", "conclusion": None if dispatch else "success"}


class API:
    def __init__(self, records=None, assets=None):
        self.records = records or {}
        self.assets = assets or {}
        self.calls = []

    def get(self, path, *, absent=False):
        self.calls.append(path)
        if path not in self.records:
            raise AssertionError("unexpected API read " + path)
        value = self.records[path]
        if value is None and not absent:
            raise R.C.ContractError("required fixture missing")
        return copy.deepcopy(value)

    def read(self, path, *, limit, asset):
        self.calls.append(path)
        value = self.assets[path]
        if len(value) > limit or not asset:
            raise R.C.ContractError("fixture byte limit")
        return 200, value


class RecoveryContextTests(unittest.TestCase):
    def test_exact_no_input_first_attempt(self):
        self.assertEqual(bound(), {"repository": "snaraj/platform", "repository_id": 1327645656,
                                   "executor_sha": SOURCE, "run_id": 500, "run_attempt": 1})
        missing_inputs = event()
        del missing_inputs["inputs"]
        self.assertEqual(R.context(environment(), missing_inputs), bound())

    def test_context_refuses_wrong_origin_identity_event_ref_attempt_or_executor(self):
        for key, value in (
            ("GITHUB_API_URL", "https://example.invalid"), ("GITHUB_REPOSITORY", "other/platform"),
            ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_RUN_ATTEMPT", "01"), ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ID", "0500"),
            ("GITHUB_RUN_ID", 500),
            ("GITHUB_RUN_ID", "٥٠٠"), ("GITHUB_SHA", "short"), ("GITHUB_WORKFLOW_SHA", "a" * 40),
            ("GITHUB_WORKFLOW_REF", "snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main"),
        ):
            changed = environment()
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                R.context(changed, event())
        for key in environment():
            changed = environment()
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                R.context(changed, event())

    def test_event_inputs_and_repository_refuse_before_api(self):
        for key, value in (("inputs", {"source": SOURCE}), ("inputs", []), ("repository", None)):
            changed = event()
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                R.context(environment(), changed)
        for key, value in (("full_name", "other/platform"), ("full_name", "snaraj/website-infrastructure"), ("id", True), ("id", 1),
                           ("default_branch", "other")):
            changed = event()
            changed["repository"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                R.context(environment(), changed)

    def test_current_main_run_and_checkout_are_independent_proofs(self):
        records = {"": REPOSITORY, "/git/ref/heads/main": {"ref": "refs/heads/main",
                    "object": {"sha": SOURCE, "type": "commit"}}, "/actions/runs/500/attempts/1": run()}
        old_name = copy.deepcopy(records)
        old_name[""]["full_name"] = "snaraj/website-infrastructure"
        old_api = API(old_name)
        with mock.patch.object(R, "prove_trees"), mock.patch.object(R.C, "_git", return_value=TREE), self.assertRaises(ValueError):
            R.prove_context(ROOT, old_api, bound())
        self.assertEqual(old_api.calls, [""])
        with mock.patch.object(R, "prove_trees") as trees, mock.patch.object(R.C, "_git", return_value=TREE):
            R.prove_context(ROOT, API(records), bound())
            trees.assert_called_once_with(ROOT, bound())
            for path, keys, value in (
                ("", ("default_branch",), "other"), ("", ("id",), 1),
                ("/git/ref/heads/main", ("object", "sha"), "a" * 40),
                ("/git/ref/heads/main", ("object", "type"), "tag"),
                ("/git/ref/heads/main", ("ref",), "refs/heads/other"),
                *( ("/actions/runs/500/attempts/1", (key,), value) for key, value in
                   (("id", 501), ("run_attempt", 2), ("event", "push"), ("head_branch", "other"),
                    ("head_sha", "a" * 40), ("path", ".github/workflows/other.yml"),
                    ("status", "completed"), ("conclusion", "success"))),
                ("/actions/runs/500/attempts/1", ("head_commit", "tree_id"), "a" * 40),
                ("/actions/runs/500/attempts/1", ("head_commit", "id"), "a" * 40),
                ("/actions/runs/500/attempts/1", ("head_repository", "id"), 1),
                ("/actions/runs/500/attempts/1", ("repository", "full_name"), "other/platform"),
            ):
                changed = copy.deepcopy(records)
                cursor = changed[path]
                for key in keys[:-1]:
                    cursor = cursor[key]
                cursor[keys[-1]] = value
                with self.subTest(path=path, keys=keys), self.assertRaises(ValueError):
                    R.prove_context(ROOT, API(changed), bound())


class RecoveryCITests(unittest.TestCase):
    def packet(self):
        jobs = ci.main_ci_jobs_record()
        qjobs = ci.codeql_jobs_record()
        for values, number in ((jobs["jobs"], 400), (qjobs["jobs"], 401)):
            for job in values:
                job.update(run_id=number, run_attempt=1, head_sha=SOURCE)
        return {"/actions/runs/400/attempts/1": run(400, workflow="pull-request.yml"),
                "/actions/runs/401/attempts/1": run(401, workflow="codeql.yml"),
                "/actions/runs/400/attempts/1/jobs?per_page=100": jobs,
                "/actions/runs/401/attempts/1/jobs?per_page=100": qjobs}

    def test_exact_attempt_endpoints_and_required_jobs(self):
        api = API(self.packet())
        R.prove_ci(api, SOURCE, TREE, (400, 1), (401, 1))
        self.assertEqual(len(api.calls), 4)
        self.assertTrue(all("/attempts/1" in path for path in api.calls))

    def test_pending_codeql_refuses_before_jobs_and_current_repository_is_exact(self):
        packet = self.packet()
        packet["/actions/runs/401/attempts/1"].update(status="in_progress", conclusion=None)
        api = API(packet)
        with self.assertRaisesRegex(ValueError, "CodeQL is not the exact"):
            R.prove_ci(api, SOURCE, TREE, (400, 1), (401, 1))
        self.assertFalse(any("/jobs?" in path for path in api.calls))
        for field in ("repository", "head_repository"):
            for replacement in (None, {**REPOSITORY, "full_name": "snaraj/website-infrastructure"}):
                packet = self.packet()
                packet["/actions/runs/400/attempts/1"][field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                    R.exact_run(API(packet), 400, 1)

    def test_original_and_executor_runs_steps_and_trees_refuse(self):
        original = self.packet()
        for number in (400, 401):
            for key, value in (("run_attempt", 2), ("status", "in_progress"), ("conclusion", "failure"),
                               ("head_sha", "a" * 40), ("event", "pull_request"), ("path", "unknown.yml")):
                changed = copy.deepcopy(original)
                changed[f"/actions/runs/{number}/attempts/1"][key] = value
                with self.subTest(number=number, key=key), self.assertRaises(ValueError):
                    R.prove_ci(API(changed), SOURCE, TREE, (400, 1), (401, 1))
        for key in ("id", "tree_id"):
            changed = copy.deepcopy(original)
            changed["/actions/runs/400/attempts/1"]["head_commit"][key] = "a" * 40
            with self.subTest(tree=key), self.assertRaises(ValueError):
                R.prove_ci(API(changed), SOURCE, TREE, (400, 1), (401, 1))
        for number in (400, 401):
            changed = copy.deepcopy(original)
            del changed[f"/actions/runs/{number}/attempts/1/jobs?per_page=100"]["jobs"][0]["steps"][2]
            with self.subTest(step=number), self.assertRaises(ValueError):
                R.prove_ci(API(changed), SOURCE, TREE, (400, 1), (401, 1))

    def test_executor_listing_never_picks_latest_from_multiple_or_partial_runs(self):
        path = f"/actions/workflows/pull-request.yml/runs?branch=main&event=push&head_sha={SOURCE}&per_page=100"
        exact = {"total_count": 1, "workflow_runs": [run(400, workflow="pull-request.yml")]}
        self.assertEqual(R.run_tuple(API({path: exact}), SOURCE, "pull-request.yml"), (400, 1))
        for count, runs in ((0, []), (2, exact["workflow_runs"]), (2, exact["workflow_runs"] * 2),
                            (True, exact["workflow_runs"]), (1, [])):
            with self.subTest(count=count, length=len(runs)), self.assertRaises(ValueError):
                R.run_tuple(API({path: {"total_count": count, "workflow_runs": runs}}), SOURCE, "pull-request.yml")
        for bad in (0, True, "400"):
            changed = copy.deepcopy(exact)
            changed["workflow_runs"][0]["id"] = bad
            with self.subTest(id=bad), self.assertRaises(ValueError):
                R.run_tuple(API({path: changed}), SOURCE, "pull-request.yml")
        with self.assertRaises(ValueError):
            R.run_tuple(API({path: {**exact, "next_page": "unbounded"}}), SOURCE, "pull-request.yml")


class RecoveryTreeTests(unittest.TestCase):
    def test_frozen_public_source_and_workflow_fingerprint(self):
        # This fingerprint was derived from the separately captured protected
        # Git trees and public run records, not computed from policy at runtime.
        value = {"sources": R.E.HISTORICAL_RELEASES, "workflows": R.E.HISTORICAL_WORKFLOWS}
        self.assertEqual(hashlib.sha256(R.canonical(value).encode()).hexdigest(),
                         "a2e9a7863d140ca4db14c57a3569f89baf1e504908b27bbb611be5a63d97745e")
        self.assertEqual((R.TERMINAL_TREE, R.TERMINAL_TAG_OBJECT, R.TERMINAL_RELEASE_ID,
                          R.TERMINAL_MAIN_RUN, R.TERMINAL_PUBLISHER_RUN),
                         ("db18c40ece8fa91f9dfabb7cb99a833a34a30505",
                          "e28add890e0af9b0be7c3a8548dad3b6fb7e9324", 384446269, 34186703418, 34186887764))

    def controls(self, altered=None):
        values = {("rev-parse", "HEAD"): SOURCE,
                  ("rev-parse", R.E.TERMINAL_V3_SOURCE + "^{tree}"): R.TERMINAL_TREE}
        fragments = {}
        for entry in R.E.HISTORICAL_RELEASES:
            sha = entry["source_sha"]
            values[("rev-parse", sha + "^{tree}")] = entry["tree_sha"]
            values[("rev-list", "--parents", "-n", "1", sha)] = sha + " " + entry["parent_sha"]
            fragments[sha] = SimpleNamespace(fragment_path=entry["fragment_path"], fragment_sha256=entry["fragment_sha256"])
        if altered and altered[0] in values:
            values[altered[0]] = altered[1]
        if altered and altered[0] in fragments:
            fragments[altered[0]] = altered[1]
        def digest(raw):
            path = raw.decode()
            value = R.E.HISTORICAL_WORKFLOWS[path]
            return SimpleNamespace(hexdigest=lambda: "0" * 64 if altered and altered[0] == path else value)
        def read_bytes(_root, *args):
            self.assertEqual(args[0], "show")
            source, path = args[1].split(":", 1)
            self.assertIn(source, {x["source_sha"] for x in R.E.HISTORICAL_RELEASES})
            return path.encode()
        return values, fragments, digest, read_bytes

    def prove(self, altered=None, ancestor=True, current=None):
        values, fragments, digest, read_bytes = self.controls(altered)
        with mock.patch.object(R.C, "_git", side_effect=lambda _root, *args: values[args]), \
                mock.patch.object(R.C, "_git_bytes", side_effect=read_bytes), \
                mock.patch.object(R.C, "_is_ancestor", return_value=ancestor), \
                mock.patch.object(R.C, "validate_transition", side_effect=lambda _root, _parent, sha, **_: fragments[sha]), \
                mock.patch.object(R.hashlib, "sha256", side_effect=digest):
            R.prove_trees(ROOT, current or bound())

    def test_historical_tree_parent_fragment_and_workflow_refusals(self):
        self.prove()
        for entry in R.E.HISTORICAL_RELEASES:
            for key in (("rev-parse", entry["source_sha"] + "^{tree}"),
                        ("rev-list", "--parents", "-n", "1", entry["source_sha"])):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.prove((key, "a" * 40))
            for field in ("fragment_path", "fragment_sha256"):
                values = {"fragment_path": entry["fragment_path"], "fragment_sha256": entry["fragment_sha256"]}
                values[field] = "changed"
                with self.subTest(source=entry["source_sha"], field=field), self.assertRaises(ValueError):
                    self.prove((entry["source_sha"], SimpleNamespace(**values)))
        for path in R.E.HISTORICAL_WORKFLOWS:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.prove((path, "changed"))
        with self.assertRaises(ValueError):
            self.prove((("rev-parse", R.E.TERMINAL_V3_SOURCE + "^{tree}"), "a" * 40))

    def test_checkout_ancestry_and_historical_executor_refusals(self):
        with self.assertRaises(ValueError):
            self.prove((("rev-parse", "HEAD"), "a" * 40))
        with self.assertRaises(ValueError):
            self.prove(ancestor=False)
        for sha in (R.E.TERMINAL_V3_SOURCE, *(x["source_sha"] for x in R.E.HISTORICAL_RELEASES)):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                self.prove((("rev-parse", "HEAD"), sha), current={**bound(), "executor_sha": sha})


class RecoverySelectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = []
        for target, name, value in (
            (R, "prove_context", None), (R, "prove_ci", None), (R, "run_tuple", (400, 1)),
            (R.C, "_git", TREE),
        ):
            patch = mock.patch.object(target, name, return_value=value)
            self.stack.append(patch)
            setattr(self, name, patch.start())
            self.addCleanup(patch.stop)

    @staticmethod
    def window(index):
        entry = R.E.HISTORICAL_RELEASES[index]
        return R.C.TransitionWindow(entry["parent_sha"], f"v0.1.{80 + index}",
            R.C.Intent(entry["source_sha"], R.C.Version(0, 1, 81 + index)),
            entry["fragment_path"], entry["fragment_sha256"])

    def select(self, index=0):
        with mock.patch.object(R, "prove_release", side_effect=[True] * (index + 1) + [False]) as releases, \
                mock.patch.object(R.C, "discover_transition_window", return_value=self.window(index)):
            value = R.selection(ROOT, API(), bound())
        self.assertEqual(releases.call_count, index + 2)
        return value

    def test_first_unresolved_edge_only_and_fresh_source_ci(self):
        for index in range(3):
            with self.subTest(index=index):
                self.prove_context.reset_mock()
                self.prove_ci.reset_mock()
                value = self.select(index)
                original = R.E.HISTORICAL_RELEASES[index]
                self.assertEqual((value["source_sha"], value["tag"]),
                                 (original["source_sha"], f"v0.1.{81 + index}"))
                self.prove_context.assert_called_once_with(ROOT, mock.ANY, bound())
                self.assertEqual(self.prove_ci.call_args_list, [
                    mock.call(mock.ANY, SOURCE, TREE, (400, 1), (400, 1)),
                    mock.call(mock.ANY, original["source_sha"], original["tree_sha"],
                              (original["main_run_id"], 1), (original["codeql_run_id"], 1)),
                ])

    def test_initial_and_resumed_selection_refuse_context_and_either_ci_failure(self):
        value = self.select()
        for supplied in (None, R.canonical(value)):
            for refused in ("context", SOURCE, value["source_sha"]):
                with self.subTest(resumed=supplied is not None, refused=refused):
                    self.prove_context.reset_mock(side_effect=True)
                    self.prove_ci.reset_mock(side_effect=True)
                    if refused == "context":
                        self.prove_context.side_effect = R.C.ContractError("proof refused")
                    else:
                        def reject_ci(_api, source, *_args):
                            if source == refused:
                                raise R.C.ContractError("proof refused")
                        self.prove_ci.side_effect = reject_ci
                    with mock.patch.object(R, "prove_release", side_effect=[True, False]), \
                            mock.patch.object(R.C, "discover_transition_window", return_value=self.window(0)), \
                            self.assertRaisesRegex(R.C.ContractError, "proof refused"):
                        R.selection(ROOT, API(), bound(), supplied)
                    if refused == "context":
                        self.prove_ci.assert_not_called()
                    elif refused == SOURCE:
                        self.prove_ci.assert_called_once_with(mock.ANY, SOURCE, TREE, (400, 1), (400, 1))

    def test_completed_window_missing_checkpoint_and_running_original_stop(self):
        for complete in (True, False):
            with mock.patch.object(R, "prove_release", return_value=complete), self.assertRaises(ValueError):
                R.selection(ROOT, API(), bound())
        with mock.patch.object(R, "prove_release", side_effect=[True, R.C.ContractError("original run pending")]) as releases, \
                self.assertRaisesRegex(ValueError, "original run pending"):
            R.selection(ROOT, API(), bound())
        self.assertEqual(releases.call_count, 2)
        with mock.patch.object(R, "prove_release", return_value=False), \
                mock.patch.object(R.C, "discover_transition_window") as ledger, \
                self.assertRaisesRegex(ValueError, "terminal v3 Release missing"):
            R.selection(ROOT, API(), bound())
        ledger.assert_not_called()

    def test_first_selection_rejects_wrong_derived_tag_or_parent_before_ci(self):
        for key, replacement in (("base_sha", "a" * 40), ("intent", R.C.Intent(SOURCE, R.C.Version(0, 1, 82)))):
            original = self.window(0)
            changed = R.C.TransitionWindow(**{**vars(original), key: replacement})
            self.prove_ci.reset_mock()
            with mock.patch.object(R, "prove_release", side_effect=[True, False]), \
                    mock.patch.object(R.C, "discover_transition_window", return_value=changed), \
                    self.assertRaisesRegex(ValueError, "derived ledger edge"):
                R.selection(ROOT, API(), bound())
            self.prove_ci.assert_not_called()

    def test_binding_bounds_bytes_before_parsing_and_finite_scope_before_ledger(self):
        value = self.select()
        oversized = R.canonical({**value, "padding": "x" * 4097})
        with mock.patch.object(R.json, "loads", wraps=json.loads) as parse, self.assertRaisesRegex(ValueError, "byte budget"):
            R.binding(ROOT, bound(), oversized)
        parse.assert_not_called()
        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            R.binding(ROOT, bound(), "[]")
        for change in ({"tag": "v0.1.84"}, {"source_sha": "a" * 40}):
            with mock.patch.object(R.C, "discover_transition_window") as ledger, \
                    self.assertRaisesRegex(ValueError, "finite window"):
                R.binding(ROOT, bound(), R.canonical({**value, **change}))
            ledger.assert_not_called()

    def test_selected_receipt_is_not_reselected_or_reused_by_another_run(self):
        value = self.select()
        with mock.patch.object(R, "prove_release", return_value=True) as releases, \
                mock.patch.object(R.C, "discover_transition_window", return_value=self.window(0)):
            self.run_tuple.reset_mock()
            self.prove_context.reset_mock()
            self.prove_ci.reset_mock()
            api = API()
            self.assertEqual(R.selection(ROOT, api, bound(), R.canonical(value)), value)
            self.run_tuple.assert_not_called()
            self.prove_context.assert_called_once_with(ROOT, api, bound())
            original = R.E.HISTORICAL_RELEASES[0]
            self.assertEqual(self.prove_ci.call_args_list, [
                mock.call(api, SOURCE, TREE, (400, 1), (400, 1)),
                mock.call(api, original["source_sha"], original["tree_sha"],
                          (original["main_run_id"], 1), (original["codeql_run_id"], 1)),
            ])
            releases.assert_called_once_with(ROOT, mock.ANY, "v0.1.80", R.E.TERMINAL_V3_SOURCE)
            for key, bad in (("run_id", 501), ("run_attempt", 2), ("executor_sha", "a" * 40),
                             ("repository_id", True), ("repository", "other/platform"),
                             ("schema", "unknown"), ("source_sha", "a" * 40), ("tag", "v0.1.84"),
                             ("base_sha", "a" * 40), ("base_tag", "v0.1.79"),
                             ("executor_main_run_id", 0), ("executor_codeql_run_attempt", True)):
                changed = dict(value)
                changed[key] = bad
                with self.subTest(key=key), self.assertRaises(ValueError):
                    R.selection(ROOT, API(), bound(), R.canonical(changed))
            for changed in (dict(value, foreign=True), {k: v for k, v in value.items() if k != "schema"}):
                with self.assertRaises(ValueError):
                    R.selection(ROOT, API(), bound(), R.canonical(changed))
            for raw in (json.dumps(value, indent=2), " " * 4097, "[]"):
                with self.assertRaises(ValueError):
                    R.selection(ROOT, API(), bound(), raw)

    def test_receipt_rechecks_predecessor_and_exact_ledger_edge(self):
        value = self.select()
        with mock.patch.object(R.C, "discover_transition_window", return_value=self.window(0)), \
                mock.patch.object(R, "prove_release", return_value=False), self.assertRaises(ValueError):
            R.selection(ROOT, API(), bound(), R.canonical(value))
        with mock.patch.object(R.C, "discover_transition_window", return_value=self.window(1)), \
                self.assertRaises(ValueError):
            R.selection(ROOT, API(), bound(), R.canonical(value))


class RecoveryReleaseTests(unittest.TestCase):
    def packet(self, value=None):
        value = v4.evidence() if value is None else value
        identity, bundle, release, runs = v4.records(value)
        for actual in runs:
            actual["head_repository"] = copy.deepcopy(REPOSITORY)
        source = value["source"]["merge_sha"]
        tag = value["tag"]["name"]
        tag_object = value["tag"]["object_sha"]
        ref = {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": tag_object}}
        annotated = {"sha": tag_object, "tag": tag, "object": {"type": "commit", "sha": source},
                     "message": f"Platform release {tag} from {source}", "tagger": {
                         "name": "github-actions[bot]", "email": R.C.RELEASE_TAGGER_EMAIL,
                         "date": "2026-09-11T00:00:00+00:00"}}
        records = {f"/git/ref/tags/{tag}": ref, f"/releases/tags/{tag}": release,
                   "/git/tags/" + tag_object: annotated}
        for actual in runs:
            records[f"/actions/runs/{actual['id']}/attempts/{actual['run_attempt']}"] = actual
        return value, API(records, {"/releases/assets/900": identity, "/releases/assets/901": bundle})

    def prove(self, value, api, *, fetched_tag=None):
        def git(_root, *args):
            if args[0] == "show":
                return "2026-09-11T00:00:00+00:00"
            if args[-1].startswith("refs/tags/"):
                return fetched_tag or value["tag"]["object_sha"]
            return value["source"]["tree_sha"]
        with mock.patch.object(R.C, "_git", side_effect=git):
            return R.prove_release(ROOT, api, value["tag"]["name"], value["source"]["merge_sha"])

    def test_exact_assets_crypto_and_original_attempt_all_required(self):
        value, api = self.packet()
        with mock.patch.object(R, "verify_signature") as crypto:
            self.assertTrue(self.prove(value, api))
            crypto.assert_called_once()
        value, api = self.packet()
        with mock.patch.object(R, "verify_signature", side_effect=subprocess.CalledProcessError(1, "cosign")), \
                self.assertRaises(subprocess.CalledProcessError):
            self.prove(value, api)
        self.assertFalse(any("/actions/runs/" in path for path in api.calls))

    def test_original_attempt_pending_failed_cancelled_missing_never_advances(self):
        for status, conclusion in (("in_progress", None), ("queued", None), ("completed", "failure"),
                                   ("completed", "cancelled"), ("unknown", None)):
            value, api = self.packet()
            api.records["/actions/runs/500/attempts/1"].update(status=status, conclusion=conclusion)
            with self.subTest(status=status, conclusion=conclusion), mock.patch.object(R, "verify_signature"), \
                    self.assertRaises(ValueError):
                self.prove(value, api)
        value, api = self.packet()
        api.records["/actions/runs/500/attempts/1"] = None
        with mock.patch.object(R, "verify_signature"), self.assertRaises(ValueError):
            self.prove(value, api)

    def test_absence_needs_both_objects_and_exact_existing_tag(self):
        value, api = self.packet()
        tag = value["tag"]["name"]
        api.records[f"/releases/tags/{tag}"] = None
        self.assertFalse(self.prove(value, api))
        api.records[f"/git/ref/tags/{tag}"] = None
        self.assertFalse(self.prove(value, api))
        value, api = self.packet()
        api.records[f"/git/ref/tags/{tag}"] = None
        with self.assertRaises(ValueError):
            self.prove(value, api)

    def test_partial_assets_oversize_wrong_target_or_foreign_tag_refuse(self):
        for change in ("partial", "oversize", "target", "tag", "immutable"):
            value, api = self.packet()
            release = api.records["/releases/tags/v0.1.81"]
            if change == "partial":
                release["assets"].pop()
            elif change == "oversize":
                release["assets"][0]["size"] = 65537
            elif change == "target":
                release["target_commitish"] = value["source"]["merge_sha"]
            elif change == "tag":
                api.records["/git/tags/" + "b" * 40]["object"]["sha"] = "a" * 40
            else:
                release["immutable"] = False
            with self.subTest(change=change), mock.patch.object(R, "verify_signature"), self.assertRaises(ValueError):
                self.prove(value, api)
            if change in {"partial", "oversize"}:
                self.assertFalse(any("/releases/assets/" in path for path in api.calls))

    def test_adapter_non_200_and_exact_pending_classification_stop(self):
        value, api = self.packet()
        original = api.read
        def non_200(*args, **kwargs):
            _status, data = original(*args, **kwargs)
            return 201, data
        api.read = non_200
        with mock.patch.object(R, "verify_signature") as crypto, self.assertRaisesRegex(ValueError, "asset download failed"):
            self.prove(value, api)
        crypto.assert_not_called()
        for status in ("queued", "in_progress", "pending", "requested", "waiting"):
            value, api = self.packet()
            api.records["/actions/runs/500/attempts/1"].update(status=status, conclusion=None)
            with self.subTest(status=status), mock.patch.object(R, "verify_signature"), self.assertRaises(R.C.PendingRelease):
                self.prove(value, api)
            # A pending-looking status cannot cover a substituted run or a
            # nonempty conclusion; these are terminal refusal, not waiting.
            for key, replacement in (("id", 501), ("conclusion", "failure")):
                changed = copy.deepcopy(api.records)
                changed["/actions/runs/500/attempts/1"][key] = replacement
                with mock.patch.object(R, "verify_signature"), self.assertRaises(R.C.ContractError) as raised:
                    self.prove(value, API(changed, api.assets))
                self.assertNotIsInstance(raised.exception, R.C.PendingRelease)

    def test_inventory_shape_names_sizes_refuse_before_any_asset_read(self):
        for change in ("tuple", "three", "duplicate", "foreign", "non-object", "bool-size", "float-size"):
            value, api = self.packet()
            release = api.records["/releases/tags/v0.1.81"]
            assets = release["assets"]
            if change == "tuple":
                release["assets"] = tuple(assets)
            elif change == "three":
                assets.append(copy.deepcopy(assets[0]))
            elif change == "duplicate":
                assets[1]["name"] = assets[0]["name"]
            elif change == "foreign":
                assets[0]["name"] = "foreign.json"
            elif change == "non-object":
                assets[0] = None
            elif change == "bool-size":
                assets[0]["size"] = True
            else:
                assets[0]["size"] = float(assets[0]["size"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prove(value, api)
            self.assertFalse(any("/releases/assets/" in path for path in api.calls))

    def test_fetched_tag_and_terminal_original_identity_are_required(self):
        value, api = self.packet()
        with self.assertRaisesRegex(ValueError, "fetched and API tag"):
            self.prove(value, api, fetched_tag="c" * 40)
        terminal = v4.evidence()
        del terminal["execution"]
        terminal.update(schema="https://snaraj.dev/schemas/platform-release-identity/v3")
        terminal["source"].update(merge_sha=R.E.TERMINAL_V3_SOURCE, tree_sha=R.TERMINAL_TREE)
        terminal["tag"].update(name="v0.1.80", object_sha=R.TERMINAL_TAG_OBJECT, peeled_commit=R.E.TERMINAL_V3_SOURCE)
        terminal["release"].update(id=R.TERMINAL_RELEASE_ID, tag_name="v0.1.80", target_commitish=R.E.TERMINAL_V3_SOURCE)
        terminal["predecessor"].update(tag="v0.1.79", peeled_commit="a" * 40)
        terminal["main_ci"].update(run_id=R.TERMINAL_MAIN_RUN, head_sha=R.E.TERMINAL_V3_SOURCE)
        terminal["platform_release"].update(run_id=R.TERMINAL_PUBLISHER_RUN, head_sha=R.E.TERMINAL_V3_SOURCE,
                                            event="workflow_run", workflow=".github/workflows/platform-release.yml")
        with mock.patch.object(R, "verify_signature"):
            self.assertTrue(self.prove(*self.packet(terminal)))
            for path in (("tag", "object_sha"), ("release", "id"), ("main_ci", "run_id"),
                         ("main_ci", "run_attempt"), ("platform_release", "run_id"), ("platform_release", "run_attempt")):
                changed = copy.deepcopy(terminal)
                changed[path[0]][path[1]] = "b" * 40 if path[1] == "object_sha" else changed[path[0]][path[1]] + 1
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "terminal v3 identity"):
                    self.prove(*self.packet(changed))


class RecoveryTransportTests(unittest.TestCase):
    def test_default_redirect_handling_is_disabled(self):
        self.assertIsNone(R.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.invalid"))
        with mock.patch.object(R.time, "monotonic", return_value=100):
            api = R.PublicAPI(None)
        self.assertEqual(api.deadline, 340)
        self.assertTrue(any(type(handler) is R.NoRedirect for handler in api.opener.handlers))
        self.assertEqual((R.MAX_JSON, R.MAX_SELECTION), (2097152, 4096))

    @staticmethod
    def response(data):
        value = io.BytesIO(data)
        value.status = 200
        return value

    def test_request_has_fixed_origin_get_and_bounded_read(self):
        api = R.PublicAPI("synthetic-read-value")
        api.opener = mock.Mock()
        api.opener.open.return_value = self.response(b"{}")
        self.assertEqual(api.get("/git/ref/heads/main"), {})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/snaraj/platform/git/ref/heads/main")
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(api.opener.open.call_args.kwargs["timeout"], 20)
        for path in (42, "https://example.invalid", "/../other", "/ref#fragment", "/ref\n", "/ref\\other"):
            api.opener.open.return_value = self.response(b"{}")
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "foreign API path"):
                api.get(path)
        api.opener.open.return_value = self.response(b"12345")
        with self.assertRaisesRegex(ValueError, "byte budget"):
            api.read("/releases/assets/1", limit=4, asset=True)

    def test_redirect_strips_authorization_and_refuses_other_hosts(self):
        api = R.PublicAPI("synthetic-read-value")
        api.opener = mock.Mock()
        url = "https://release-assets.githubusercontent.com/example?signature=synthetic"
        redirect = urllib.error.HTTPError("", 302, "redirect", {"Location": url}, None)
        api.opener.open.side_effect = [redirect, self.response(b"data")]
        self.assertEqual(api.read("/releases/assets/1", asset=True), (200, b"data"))
        first, second = [call.args[0] for call in api.opener.open.call_args_list]
        self.assertIn("Authorization", dict(first.header_items()))
        self.assertNotIn("Authorization", dict(second.header_items()))
        user_target = "https://" + "@".join(("synthetic-user", "release-assets.githubusercontent.com/a"))
        password_target = "https://" + "@".join((":synthetic-password", "release-assets.githubusercontent.com/a"))
        for target in ("http://release-assets.githubusercontent.com/a", "https://example.invalid/a",
                       "https://release-assets.githubusercontent.com:444/a", user_target, password_target,
                       "https://release-assets.githubusercontent.com/a#fragment"):
            api.opener.open.side_effect = [urllib.error.HTTPError("", 302, "redirect", {"Location": target}, None), self.response(b"data")]
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "foreign asset redirect"):
                api.read("/releases/assets/1", asset=True)

    def test_non_object_and_non_200_success_responses_refuse(self):
        api = R.PublicAPI(None)
        api.opener = mock.Mock()
        for raw in (b"[]", b"0", b"null"):
            api.opener.open.return_value = self.response(raw)
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "object response"):
                api.get("/required")
        api.opener.open.return_value = self.response(b"{}")
        api.opener.open.return_value.status = 201
        with self.assertRaisesRegex(ValueError, "return 200"):
            api.get("/required")

    def test_required_missing_permission_unknown_and_read_budgets_refuse(self):
        api = R.PublicAPI(None)
        api.opener = mock.Mock()
        for status in (401, 403, 404, 500, 302):
            api.opener.open.side_effect = urllib.error.HTTPError("", status, "synthetic", {}, None)
            with self.subTest(status=status), self.assertRaises(ValueError):
                api.get("/required")
        api.opener.open.side_effect = urllib.error.HTTPError("", 404, "synthetic", {}, None)
        self.assertIsNone(api.get("/optional", absent=True))
        api.requests = 96
        with self.assertRaisesRegex(ValueError, "read budget"):
            api.get("/required")
        api.requests = 0
        api.deadline = 0
        with self.assertRaisesRegex(ValueError, "read budget"):
            api.get("/required")


class RecoveryCLITests(unittest.TestCase):
    def test_bind_rechecks_context_trees_receipt_and_every_publisher_field(self):
        entry = R.E.HISTORICAL_RELEASES[0]
        value = {"schema": R.SELECTION_SCHEMA, **bound(), "source_sha": entry["source_sha"],
                 "tag": "v0.1.81", "base_sha": entry["parent_sha"], "base_tag": "v0.1.80",
                 "executor_main_run_id": 400, "executor_main_run_attempt": 1,
                 "executor_codeql_run_id": 401, "executor_codeql_run_attempt": 1}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(path), "RECOVERY_SELECTION": R.canonical(value),
                   **{key.upper(): value[key] for key in ("source_sha", "tag", "base_sha", "base_tag")},
                   "MAIN_RUN_ID": str(entry["main_run_id"]), "MAIN_RUN_ATTEMPT": "1",
                   "EXECUTION_MAIN_RUN_ID": "400", "EXECUTION_MAIN_RUN_ATTEMPT": "1"}
            cases = [{}, *({key: "wrong"} for key in ("SOURCE_SHA", "TAG", "BASE_SHA", "BASE_TAG", "MAIN_RUN_ID",
                       "MAIN_RUN_ATTEMPT", "EXECUTION_MAIN_RUN_ID", "EXECUTION_MAIN_RUN_ATTEMPT")),
                     {"GITHUB_RUN_ID": "501"}, {"RECOVERY_SELECTION": R.canonical({**value, "run_id": 501})}]
            for change in cases:
                with self.subTest(change=change), mock.patch.dict(os.environ, {**env, **change}, clear=True), \
                        mock.patch.object(R, "prove_trees") as trees, mock.patch.object(R, "PublicAPI") as api, \
                        mock.patch.object(R.C, "discover_transition_window", return_value=RecoverySelectionTests.window(0)), \
                        mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(R.main(["bind"]), 1 if change else 0)
                    trees.assert_called_once()
                    api.assert_not_called()

    def test_predecessor_cli_preserves_pending_failure_and_no_credential_inheritance(self):
        env = {"GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "snaraj/platform",
               "GITHUB_REPOSITORY_ID": "1327645656", "SOURCE_SHA": SOURCE,
               "RECOVERY_READ_TOKEN": "synthetic-read-value"}
        for outcome, code in ((True, 0), (False, 1), (R.C.PendingRelease("original pending"), 3),
                              (R.C.ContractError("original failed"), 1)):
            options = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with self.subTest(outcome=outcome), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(R.C, "discover_transition_window", return_value=RecoverySelectionTests.window(0)), \
                    mock.patch.object(R, "prove_release", **options) as prove, mock.patch.object(R, "PublicAPI") as api, \
                    mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(R.main(["predecessor"]), code)
                self.assertNotIn("RECOVERY_READ_TOKEN", os.environ)
                api.assert_called_once_with("synthetic-read-value")
                self.assertEqual(prove.call_args.args[-2:], ("v0.1.80", R.E.TERMINAL_V3_SOURCE))
        for changed in ({"GITHUB_API_URL": "https://example.invalid"},
                        {"GITHUB_REPOSITORY": "snaraj/website-infrastructure"}, {"GITHUB_REPOSITORY_ID": "1"}):
            with mock.patch.dict(os.environ, {**env, **changed}, clear=True), mock.patch.object(R, "prove_release") as prove, \
                    mock.patch.object(R.C, "discover_transition_window") as ledger, \
                    mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(R.main(["predecessor"]), 1)
                prove.assert_not_called()
                ledger.assert_not_called()

    def test_oversize_selected_output_is_refused_before_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            output = Path(directory) / "outputs"
            value = {**bound(), "source_sha": SOURCE, "padding": "x" * 4097}
            env = {**environment(), "GITHUB_EVENT_PATH": str(path), "GITHUB_OUTPUT": str(output)}
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(R, "selection", return_value=value), \
                    mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(R.main(["prepare"]), 1)
            self.assertFalse(output.exists())

    def test_prepare_and_verify_do_not_leak_or_inherit_the_read_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "event.json").write_text(json.dumps(event()))
            output = root / "outputs"
            env = {**environment(), "GITHUB_EVENT_PATH": str(root / "event.json"),
                   "GITHUB_OUTPUT": str(output), "RECOVERY_READ_TOKEN": "synthetic-read-value"}
            value = {**bound(), "source_sha": R.E.HISTORICAL_RELEASES[0]["source_sha"]}
            for command in ("prepare", "verify"):
                selected = {**env, **({"RECOVERY_SELECTION": "{}"} if command == "verify" else {})}
                with mock.patch.dict(os.environ, selected, clear=True), \
                        mock.patch.object(R, "selection", return_value=value) as selection, \
                        mock.patch.object(R, "PublicAPI") as api, mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    self.assertEqual(R.main([command]), 0)
                    self.assertNotIn("RECOVERY_READ_TOKEN", os.environ)
                    api.assert_called_once_with("synthetic-read-value")
                    self.assertEqual(selection.call_args.args[-1], "{}" if command == "verify" else None)
                    self.assertNotIn("synthetic-read-value", stdout.getvalue())
            self.assertEqual(output.read_text().count("selection="), 1)
            self.assertIn(value["source_sha"], output.read_text())

    def test_cli_refuses_ambient_credentials_bad_mode_and_oversize_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(path), "GITHUB_OUTPUT": str(Path(directory) / "outputs")}
            cases = [{name: "synthetic"} for name in ("GH_TOKEN", "GITHUB_TOKEN", "IMMUTABLE_SETTINGS_TOKEN",
                "ACTIONS_READ_TOKEN", "CONTENTS_READ_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")]
            cases.extend([{"RECOVERY_SELECTION": "{}"}, {"GITHUB_RUN_ATTEMPT": "2"}])
            for changed in cases:
                with self.subTest(changed=tuple(changed)), mock.patch.dict(os.environ, {**env, **changed}, clear=True), \
                        mock.patch.object(R, "selection") as select, mock.patch("sys.stderr", new_callable=io.StringIO):
                    self.assertEqual(R.main(["prepare"]), 1)
                    select.assert_not_called()
            path.write_bytes(json.dumps(event()).encode() + b" " * (R.MAX_JSON + 1))
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(R, "selection") as select, \
                    mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(R.main(["prepare"]), 1)
                select.assert_not_called()

    def test_crypto_uses_external_subject_issuer_and_actual_executor(self):
        value = v4.evidence()
        identity, bundle, _, _ = v4.records(value)
        with mock.patch.object(R.subprocess, "run") as execute:
            R.verify_signature(identity, bundle, "v0.1.81")
            arguments = execute.call_args.args[0]
            for flag, expected in (("--certificate-identity", "https://github.com/snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main"),
                                   ("--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"),
                                   ("--certificate-github-workflow-sha", SOURCE),
                                   ("--certificate-github-workflow-trigger", "workflow_dispatch"), ("--timeout", "30s")):
                self.assertEqual(arguments[arguments.index(flag) + 1], expected)
            self.assertTrue(execute.call_args.kwargs["check"])
            self.assertLessEqual(execute.call_args.kwargs["timeout"], 40)
            self.assertFalse(Path(arguments[-1]).exists())


if __name__ == "__main__":
    unittest.main()
