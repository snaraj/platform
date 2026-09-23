"""Offline policy controls for the tag-derived source-backlog recovery reader.

Issue #395 removed the hand-frozen window these tests used to read. What they
assert now is the derivation itself: the repository's own tag ledger is the
window, the executor relation replaces the membership refusal and its pins, the
reader proves the predecessor rather than all of history, and one dispatch
drains every pending edge.
"""

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
from unittest import mock

from .support import load_script
from . import test_platform_release_v4 as v4

ROOT = Path(__file__).resolve().parents[2]
R = load_script("ci/platform_release_recovery.py", module_name="recovery_policy_tests")
B = R.B
SOURCE = "e" * 40
TREE = "f" * 40
REPOSITORY = {"id": 1327645656, "full_name": "snaraj/platform", "default_branch": "main"}
# The ledger these tests drive is read from the committed derivation dump, not
# re-walked from the 86 post-floor tags in every test: `LedgerDerivationTests`
# proves the shipped code reproduces that dump from git, once.
DERIVED_WINDOW = v4.DERIVED_WINDOW
LEDGER = v4.LEDGER


REAL_NO_PUBLISHER = R.prove_no_publisher_in_flight


def ledger_patch():
    """Serve the dump-derived ledger wherever production would walk git."""
    return mock.patch.object(B, "published_edges", return_value=LEDGER)


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


def selection_of(edges, **overrides):
    """A canonical selection list over the given derived edges."""
    value = {"schema": R.SELECTION_SCHEMA, **bound(),
             "edges": [R.edge_record(edge, (600 + index, 1), (700 + index, 1))
                       for index, edge in enumerate(edges)],
             "executor_main_run_id": 400, "executor_main_run_attempt": 1,
             "executor_codeql_run_id": 401, "executor_codeql_run_attempt": 1}
    value.update(overrides)
    return value


class API:
    def __init__(self, records=None, assets=None):
        self.records = records or {}
        self.assets = assets or {}
        self.calls = []
        self.requests = 0
        self.max_reads, self.max_seconds = R.per_run_bounds(1)
        self.elapsed = 0.0

    def widen(self, pending):
        self.max_reads, _ = R.per_run_bounds(pending)

    def get(self, path, *, absent=False):
        self.calls.append(path)
        self.requests += 1
        if path not in self.records:
            if absent and path.startswith("/git/ref/tags/"):
                return None
            raise AssertionError("unexpected API read " + path)
        value = self.records[path]
        if value is None and not absent:
            raise R.C.ContractError("required fixture missing")
        return copy.deepcopy(value)

    def read(self, path, *, limit, asset):
        self.calls.append(path)
        self.requests += 1
        value = self.assets[path]
        if len(value) > limit or not asset:
            raise R.C.ContractError("fixture byte limit")
        return 200, value


class RecoveryContextTests(unittest.TestCase):
    def test_exact_no_input_first_attempt(self):
        self.assertEqual(bound(), {"repository": "snaraj/platform", "repository_id": 1327645656,
                                   "executor_sha": SOURCE, "run_id": 500, "run_attempt": 1})

    def test_context_refuses_wrong_origin_identity_event_ref_attempt_or_executor(self):
        for key, value in (("GITHUB_API_URL", "https://example.invalid"),
                           ("GITHUB_REPOSITORY", "snaraj/website-infrastructure"),
                           ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_REF", "refs/heads/other"), ("GITHUB_RUN_ATTEMPT", "2"),
                           ("GITHUB_SHA", "short"), ("GITHUB_WORKFLOW_SHA", "a" * 40),
                           ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ID", "abc"),
                           ("GITHUB_WORKFLOW_REF", "snaraj/platform/.github/workflows/other.yml@refs/heads/main")):
            values = environment()
            values[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                R.context(values, event())
        for key in environment():
            values = environment()
            del values[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                R.context(values, event())

    def test_event_inputs_and_repository_refuse_before_api(self):
        for change in ({"inputs": {"source": "x"}}, {"repository": {}},
                       {"repository": {**REPOSITORY, "id": 1}},
                       {"repository": {**REPOSITORY, "default_branch": "other"}},
                       {"repository": None}):
            payload = {**event(), **change}
            with self.subTest(change=tuple(change)), self.assertRaises(ValueError):
                R.context(environment(), payload)

    def test_current_main_run_and_checkout_are_independent_proofs(self):
        records = {"": copy.deepcopy(REPOSITORY),
                   "/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": SOURCE}},
                   "/actions/runs/500/attempts/1": run()}
        with mock.patch.object(R, "prove_trees") as trees, \
                mock.patch.object(R.C, "_git", return_value=TREE):
            R.prove_context(ROOT, API(copy.deepcopy(records)), bound())
            trees.assert_called_once()
        for path, change in (("", {"default_branch": "other"}), ("", {"id": 1}),
                             ("/git/ref/heads/main", {"object": {"type": "commit", "sha": "a" * 40}}),
                             ("/git/ref/heads/main", {"ref": "refs/heads/other"}),
                             ("/actions/runs/500/attempts/1", {"event": "push"}),
                             ("/actions/runs/500/attempts/1", {"status": "completed"}),
                             ("/actions/runs/500/attempts/1", {"conclusion": "success"}),
                             ("/actions/runs/500/attempts/1", {"path": ".github/workflows/platform-release.yml"}),
                             ("/actions/runs/500/attempts/1", {"head_commit": {"id": SOURCE, "tree_id": "a" * 40}})):
            changed = copy.deepcopy(records)
            changed[path] = {**changed[path], **change}
            with self.subTest(path=path, change=tuple(change)), mock.patch.object(R, "prove_trees"), \
                    mock.patch.object(R.C, "_git", return_value=TREE), self.assertRaises(ValueError):
                R.prove_context(ROOT, API(changed), bound())


class RecoveryTreeTests(unittest.TestCase):
    """What the checkout must prove is now two facts, not a table walk."""

    def test_checkout_must_be_the_executor_and_the_checkpoint_tree_exact(self):
        values = {("rev-parse", "HEAD"): SOURCE,
                  ("rev-parse", R.E.TERMINAL_V3_SOURCE + "^{tree}"): R.TERMINAL_TREE}
        with mock.patch.object(R.C, "_git", side_effect=lambda _root, *args: values[args]):
            R.prove_trees(ROOT, bound())
        for key, replacement in ((("rev-parse", "HEAD"), "a" * 40),
                                 (("rev-parse", R.E.TERMINAL_V3_SOURCE + "^{tree}"), "a" * 40)):
            changed = {**values, key: replacement}
            with self.subTest(key=key), \
                    mock.patch.object(R.C, "_git", side_effect=lambda _root, *args: changed[args]), \
                    self.assertRaises(ValueError):
                R.prove_trees(ROOT, bound())

    def test_the_checkpoint_constants_are_the_frozen_ones(self):
        self.assertEqual((R.TERMINAL_TREE, R.TERMINAL_TAG_OBJECT, R.TERMINAL_RELEASE_ID,
                          R.TERMINAL_MAIN_RUN, R.TERMINAL_PUBLISHER_RUN),
                         ("db18c40ece8fa91f9dfabb7cb99a833a34a30505",
                          "e28add890e0af9b0be7c3a8548dad3b6fb7e9324", 384446269, 34186703418, 34186887764))


class LedgerDerivationTests(unittest.TestCase):
    """A1: the derivation reproduces every fact the deleted table transcribed.

    The committed side-by-side dump was taken at the base commit, while the
    table still existed, from the repository's own objects and the GitHub run
    listings. These tests re-derive the same facts with the shipped code and
    compare, so the artifact cannot drift away from what the code does.
    """

    def test_the_committed_dump_is_byte_equal_for_every_retired_row(self):
        self.assertTrue(DERIVED_WINDOW["byte_equal"])
        self.assertEqual(len(DERIVED_WINDOW["edges"]), 13)
        for row in DERIVED_WINDOW["edges"]:
            with self.subTest(tag=row["tag"]):
                self.assertTrue(row["byte_equal"])
                self.assertEqual(row["table"], row["derived"])
                for name in ("main", "codeql"):
                    record = row["original_runs"][name]
                    self.assertEqual(record["conclusion"], "success")
                    self.assertEqual(record["status"], "completed")

    def test_the_shipped_derivation_reproduces_the_dump_from_git(self):
        rows = {row["tag"]: row["derived"] for row in DERIVED_WINDOW["edges"]}
        edges = {edge.tag: edge for edge in LEDGER}
        self.assertLessEqual(set(rows), set(edges))
        for tag, expected in rows.items():
            edge = edges[tag]
            with self.subTest(tag=tag):
                self.assertEqual(edge.source_sha, expected["source_sha"])
                self.assertEqual(edge.tree_sha, expected["tree_sha"])
                self.assertEqual(edge.parent_sha, expected["parent_sha"])
                self.assertEqual(edge.fragment_path, expected["fragment_path"])
                self.assertEqual(edge.fragment_sha256, expected["fragment_sha256"])
                self.assertEqual(dict(edge.workflows), expected["workflows"])

    def test_the_ledger_is_the_window_and_chains_from_the_checkpoint(self):
        self.assertEqual(len(LEDGER), 13)
        previous_tag, previous_sha = R.E.TERMINAL_V3_TAG, R.E.TERMINAL_V3_SOURCE
        for edge in LEDGER:
            self.assertEqual((edge.base_tag, edge.base_sha), (previous_tag, previous_sha))
            self.assertEqual(R.E.next_tag(previous_tag), edge.tag)
            previous_tag, previous_sha = edge.tag, edge.source_sha
        self.assertEqual(LEDGER[0].tag, R.E.FIRST_V4_TAG)

    def test_a_derived_edge_refuses_a_merge_commit_source(self):
        merge = R.C._git(ROOT, "rev-list", "--max-count=1", "--merges", "HEAD")
        if not merge:
            self.skipTest("this history carries no merge commit to refuse")
        with self.assertRaisesRegex(ValueError, "single-parent"):
            B.derive_edge(ROOT, tag="v9.9.9", source_sha=merge,
                          base_tag=LEDGER[-1].tag, base_sha=LEDGER[-1].source_sha)


class RecoveryCITests(unittest.TestCase):
    def listing(self, run_id, source=SOURCE, workflow="pull-request.yml", **changes):
        record = {**run(run_id, workflow=workflow, source=source), **changes}
        return {"total_count": 1, "workflow_runs": [record]}

    def test_the_original_run_listing_must_be_one_successful_latest_attempt(self):
        path = ("/actions/workflows/pull-request.yml/runs?branch=main&event=push"
                f"&head_sha={SOURCE}&per_page=100")
        api = API({path: self.listing(400)})
        self.assertEqual(R.run_tuple(api, SOURCE, "pull-request.yml"), (400, 1))
        # The LATEST attempt is what the ordinary publisher consumes, so a
        # later successful attempt is admitted and an unsuccessful one is not.
        api = API({path: self.listing(400, run_attempt=3)})
        self.assertEqual(R.run_tuple(api, SOURCE, "pull-request.yml"), (400, 3))
        for change in ({"conclusion": "failure"}, {"conclusion": None},
                       {"status": "in_progress", "conclusion": None}):
            with self.subTest(change=tuple(change)), \
                    self.assertRaisesRegex(ValueError, "did not conclude success"):
                R.run_tuple(API({path: self.listing(400, **change)}), SOURCE, "pull-request.yml")
        for listing in ({"total_count": 0, "workflow_runs": []},
                        {"total_count": 2, "workflow_runs": [run(400), run(401)]},
                        {"total_count": 1, "workflow_runs": [run(400), run(401)]},
                        {"total_count": 2, "workflow_runs": [run(400)]},
                        {"total_count": 1, "workflow_runs": [run(400)], "extra": 1}):
            with self.subTest(listing=listing), \
                    self.assertRaisesRegex(ValueError, "exactly one complete main workflow listing"):
                R.run_tuple(API({path: listing}), SOURCE, "pull-request.yml")

    def test_exact_attempt_endpoints_and_required_jobs(self):
        api = API({"/actions/runs/400/attempts/1": run(400, workflow="pull-request.yml"),
                   "/actions/runs/401/attempts/1": run(401, workflow="codeql.yml"),
                   "/actions/runs/400/attempts/1/jobs?per_page=100": {"jobs": []},
                   "/actions/runs/401/attempts/1/jobs?per_page=100": {"jobs": []}})
        with mock.patch.object(R.C, "build_main_ci_jobs_receipt") as receipt, \
                mock.patch.object(R.C, "classify_codeql_run", return_value=(401, 1)), \
                mock.patch.object(R.C, "plan_workflow_run", return_value=SOURCE):
            R.prove_ci(api, SOURCE, TREE, (400, 1), (401, 1))
            receipt.assert_called_once()
        self.assertEqual(api.calls, ["/actions/runs/400/attempts/1", "/actions/runs/401/attempts/1",
                                     "/actions/runs/400/attempts/1/jobs?per_page=100",
                                     "/actions/runs/401/attempts/1/jobs?per_page=100"])

    def test_pending_codeql_and_foreign_repository_refuse(self):
        records = {"/actions/runs/400/attempts/1": run(400, workflow="pull-request.yml"),
                   "/actions/runs/401/attempts/1": run(401, workflow="codeql.yml")}
        with mock.patch.object(R.C, "classify_codeql_run", return_value=None), \
                mock.patch.object(R.C, "plan_workflow_run", return_value=SOURCE), \
                self.assertRaisesRegex(ValueError, "exact successful attempt"):
            R.prove_ci(API(copy.deepcopy(records)), SOURCE, TREE, (400, 1), (401, 1))
        changed = copy.deepcopy(records)
        changed["/actions/runs/400/attempts/1"]["repository"] = {"id": 1, "full_name": "snaraj/platform"}
        with self.assertRaises(ValueError):
            R.exact_run(API(changed), 400, 1)
        changed = copy.deepcopy(records)
        changed["/actions/runs/400/attempts/1"]["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "run attempt substitution"):
            R.exact_run(API(changed), 400, 1)

    def test_the_receipt_is_the_same_control_the_ordinary_path_runs(self):
        """`prove_ci` and the ordinary jobs verifier share one receipt builder.

        The frozen workflow-digest inventory is gone; what enforces the source's
        required jobs is this receipt, and it must be the ordinary path's.
        """
        verifier = (ROOT / "scripts/ci/verify-platform-release-main-jobs.sh").read_text()
        self.assertIn('"${contract}" main-ci-jobs-receipt', verifier)
        source = (ROOT / "scripts/ci/platform_release_recovery.py").read_text()
        self.assertIn("C.build_main_ci_jobs_receipt(", source)
        self.assertIn("repository-and-infrastructure", R.C.REQUIRED_CHECKS)
        self.assertIn("dependency-review", R.C.REQUIRED_CHECKS)


class RecoverySelectionTests(unittest.TestCase):
    """The newest-first scan, the ordered list, and what refuses it."""

    def setUp(self):
        for target, name, value in ((R, "prove_context", None), (R, "prove_ci", None),
                                    (R, "prove_no_publisher_in_flight", None),
                                    (R, "prove_tag", "a" * 40),
                                    (R, "run_tuple", (400, 1))):
            patch = mock.patch.object(target, name, return_value=value)
            setattr(self, name, patch.start())
            self.addCleanup(patch.stop)
        patch = mock.patch.object(R.C, "_git", return_value=TREE)
        self.git = patch.start()
        self.addCleanup(patch.stop)

    def select(self, published, stream=None):
        """One `prepare` selection whose first `published` ledger edges exist."""
        present = {edge.tag for edge in LEDGER[:published]}
        with ledger_patch(), mock.patch.object(R, "release_present",
                               side_effect=lambda _api, tag: tag in present), \
                mock.patch.object(R, "prove_release", return_value=True) as prove:
            value = R.selection(ROOT, API(), bound(), stream=stream or io.StringIO())
        return value, prove

    def test_every_pending_edge_is_selected_in_ledger_order(self):
        for published in (len(LEDGER) - 1, len(LEDGER) - 4, 0):
            with self.subTest(published=published):
                value, prove = self.select(published)
                self.assertEqual([entry["tag"] for entry in value["edges"]],
                                 [edge.tag for edge in LEDGER[published:]])
                # The predecessor is proved in full; the published edges before
                # it are not re-proved at all.
                proved = [call.args[2] for call in prove.call_args_list]
                expected = [R.E.TERMINAL_V3_TAG]
                if published:
                    expected.append(LEDGER[published - 1].tag)
                self.assertEqual(proved, expected)
                for entry, edge in zip(value["edges"], LEDGER[published:]):
                    self.assertEqual(entry["source_sha"], edge.source_sha)
                    self.assertEqual(entry["tree_sha"], edge.tree_sha)
                    self.assertEqual(entry["fragment_sha256"], edge.fragment_sha256)
                    self.assertEqual(entry["workflows"], dict(edge.workflows))

    def test_a_complete_backlog_refuses_by_name(self):
        with self.assertRaisesRegex(ValueError, "backlog is complete; use the ordinary publisher"):
            self.select(len(LEDGER))

    def test_an_in_flight_ordinary_publisher_refuses_by_name(self):
        self.prove_no_publisher_in_flight.side_effect = R.C.ContractError(
            "ordinary platform-release publisher is queued or in progress")
        with self.assertRaisesRegex(ValueError, "queued or in progress"):
            self.select(len(LEDGER) - 1)
        for status in R.IN_FLIGHT:
            api = API({"/actions/workflows/platform-release.yml/runs?branch=main&per_page=1":
                       {"total_count": 1, "workflow_runs": [{"status": status}]}})
            with self.subTest(status=status), \
                    self.assertRaisesRegex(ValueError, "queued or in progress"):
                REAL_NO_PUBLISHER(api)
        api = API({"/actions/workflows/platform-release.yml/runs?branch=main&per_page=1":
                   {"total_count": 1, "workflow_runs": [{"status": "completed"}]}})
        REAL_NO_PUBLISHER(api)
        for listing in ({"total_count": 0}, {"workflow_runs": {}}, {"extra": 1}):
            api = API({"/actions/workflows/platform-release.yml/runs?branch=main&per_page=1": listing})
            with self.subTest(listing=listing), \
                    self.assertRaisesRegex(ValueError, "publisher run listing is malformed"):
                REAL_NO_PUBLISHER(api)

    def test_each_pending_edge_proves_its_tag_and_its_own_original_ci(self):
        value, _ = self.select(len(LEDGER) - 3)
        pending = LEDGER[-3:]
        self.assertEqual([call.args[2] for call in self.prove_tag.call_args_list],
                         [edge.tag for edge in pending])
        # The executor's CI, then one proof per pending edge at its own tree.
        self.assertEqual([call.args[1] for call in self.prove_ci.call_args_list],
                         [bound()["executor_sha"], *[edge.source_sha for edge in pending]])
        self.assertEqual([call.args[2] for call in self.prove_ci.call_args_list][1:],
                         [edge.tree_sha for edge in pending])
        self.assertEqual(len(value["edges"]), 3)

    def test_the_log_names_every_edge_and_the_run_totals(self):
        stream = io.StringIO()
        value, _ = self.select(len(LEDGER) - 2, stream=stream)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len([line for line in lines if line.startswith("RECOVERY_EDGE ")]), 2)
        for entry, line in zip(value["edges"], lines):
            self.assertIn(f"tag={entry['tag']}", line)
            self.assertIn(f"source={entry['source_sha']}", line)
            self.assertIn("reads=", line)
            self.assertIn("seconds=", line)
            self.assertIn("decision=selected", line)
        summary = lines[-1]
        self.assertTrue(summary.startswith("RECOVERY_SUMMARY pending=2 published=0 reads="))
        self.assertIn("/", summary.split("reads=")[1])

    def test_the_list_must_be_the_ledger_and_nothing_else(self):
        value, _ = self.select(len(LEDGER) - 4)
        with ledger_patch():
            R.binding(ROOT, bound(), R.canonical(value))
        edges = value["edges"]
        cases = {
            "reordered": [edges[1], edges[0], *edges[2:]],
            "dropped": [edges[0], *edges[2:]],
            "duplicated": [*edges, copy.deepcopy(edges[-1])],
            "rechained": [{**edges[0], "base_tag": edges[1]["base_tag"]}, *edges[1:]],
            "foreign field": [{**edges[0], "extra": 1}, *edges[1:]],
            "missing field": [{k: v for k, v in edges[0].items() if k != "tree_sha"}, *edges[1:]],
            "moved fragment": [{**edges[0], "fragment_sha256": "0" * 64}, *edges[1:]],
            "moved tree": [{**edges[0], "tree_sha": "0" * 40}, *edges[1:]],
            "moved workflow digest": [{**edges[0], "workflows": {}}, *edges[1:]],
            "zero run": [{**edges[0], "main_run_id": 0}, *edges[1:]],
            "empty": [],
        }
        with ledger_patch():
            for name, replacement in cases.items():
                with self.subTest(case=name), self.assertRaises(ValueError):
                    R.binding(ROOT, bound(), R.canonical({**value, "edges": replacement}))
            for key, replacement in (("run_id", 501), ("run_attempt", 2), ("executor_sha", "a" * 40),
                                     ("repository", "other/platform"), ("repository_id", True),
                                     ("schema", "unknown"), ("executor_main_run_id", 0),
                                     ("executor_codeql_run_attempt", True)):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    R.binding(ROOT, bound(), R.canonical({**value, key: replacement}))
            for raw in (json.dumps(value, indent=2), "[]", " " * 8):
                with self.subTest(raw=raw[:8]), self.assertRaises(ValueError):
                    R.binding(ROOT, bound(), raw)
            for changed in (dict(value, foreign=True),
                            {k: v for k, v in value.items() if k != "schema"}):
                with self.assertRaises(ValueError):
                    R.binding(ROOT, bound(), R.canonical(changed))

    def test_the_byte_budget_is_derived_and_checked_before_parsing(self):
        value, _ = self.select(len(LEDGER) - 2)
        # The absolute cap is checked before the payload is parsed at all.
        oversized = R.canonical(
            {**value, "padding": "x" * R.selection_bytes(R.C.MAX_TAG_LEDGER_ENTRIES)})
        with ledger_patch(), mock.patch.object(R.json, "loads", wraps=json.loads) as parse, \
                self.assertRaisesRegex(ValueError, "byte budget"):
            R.binding(ROOT, bound(), oversized)
        parse.assert_not_called()
        # And a list is then held to the budget its OWN length derives.
        padded = R.canonical({**value, "edges": [
            {**entry, "fragment_path": "changelog.d/1-" + "a" * 200 + ".md"}
            for entry in value["edges"]]})
        with ledger_patch(), self.assertRaisesRegex(ValueError, "byte budget"):
            R.binding(ROOT, bound(), padded)
        self.assertGreater(R.selection_bytes(4), R.selection_bytes(1))
        self.assertEqual(R.selection_bytes(4) - R.selection_bytes(3),
                         R.selection_bytes(3) - R.selection_bytes(2))
        for pending in (0, -1, True, 1.0, "1", None):
            with self.subTest(pending=pending), self.assertRaises(ValueError):
                R.selection_bytes(pending)

    def test_a_supplied_list_is_not_reselected_and_stays_bound_to_its_run(self):
        value, _ = self.select(len(LEDGER) - 2)
        with ledger_patch(), mock.patch.object(R, "prove_release", return_value=True) as prove, \
                mock.patch.object(R, "release_present") as present:
            self.run_tuple.reset_mock()
            self.assertEqual(R.selection(ROOT, API(), bound(), R.canonical(value),
                                         stream=io.StringIO()), value)
            present.assert_not_called()
            # The executor's own run listing is taken from the receipt, never
            # reselected; each edge's ORIGINAL CI is re-derived and compared.
            self.assertEqual([call.args[1] for call in self.run_tuple.call_args_list],
                             [edge.source_sha for edge in LEDGER[-2:] for _ in range(2)])
            self.assertEqual([call.args[2] for call in prove.call_args_list],
                             [R.E.TERMINAL_V3_TAG, LEDGER[-3].tag])


class RecoveryDrainTests(unittest.TestCase):
    """A3: a four-edge simulated backlog drained in ONE dispatch."""

    class Store:
        """An in-memory tag/Release store the shell loop drives through jq."""

        def __init__(self, edges, published):
            self.edges = edges
            self.released = {edge.tag for edge in published}
            self.drafts = {}
            self.log = []

        def present(self, _api, tag):
            return tag in self.released

        def publish(self, tag, *, assets=2, refuse=None):
            if refuse:
                self.log.append(("refused", tag, refuse))
                raise R.C.ContractError(refuse)
            if assets != 2:
                self.drafts[tag] = assets
                self.log.append(("draft", tag, assets))
                raise R.C.ContractError("partial or foreign release remains held")
            self.drafts.pop(tag, None)
            self.released.add(tag)
            self.log.append(("published", tag, assets))

    def setUp(self):
        self.pending = LEDGER[-4:]
        self.published = LEDGER[:-4]
        for name in ("prove_context", "prove_ci", "prove_no_publisher_in_flight"):
            patch = mock.patch.object(R, name, return_value=None)
            setattr(self, name, patch.start())
            self.addCleanup(patch.stop)
        for name, value in (("prove_tag", "a" * 40), ("run_tuple", (400, 1))):
            patch = mock.patch.object(R, name, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(R.C, "_git", return_value=TREE)
        patch.start()
        self.addCleanup(patch.stop)

    def prepare(self, store):
        with ledger_patch(), mock.patch.object(R, "release_present", side_effect=store.present), \
                mock.patch.object(R, "prove_release", return_value=True):
            return R.selection(ROOT, API(), bound(), stream=io.StringIO())

    def drain(self, store, *, refusals=None, drafts=None):
        """Loop the selection exactly as publish-platform-recovery.sh does."""
        selected = self.prepare(store)
        refusals, drafts = refusals or {}, drafts or {}
        published, stopped = [], None
        for entry in selected["edges"]:
            try:
                store.publish(entry["tag"], assets=drafts.get(entry["tag"], 2),
                              refuse=refusals.get(entry["tag"]))
            except R.C.ContractError as error:
                stopped = (entry["tag"], str(error))
                break
            # The independent readback after each edge.
            with mock.patch.object(R, "prove_release", return_value=True) as readback:
                self.assertTrue(readback(ROOT, API(), entry["tag"], entry["source_sha"]))
            published.append(entry["tag"])
        return selected, published, stopped

    def test_one_dispatch_selects_and_publishes_all_four_in_order(self):
        store = self.Store(LEDGER, self.published)
        selected, published, stopped = self.drain(store)
        self.assertEqual([entry["tag"] for entry in selected["edges"]],
                         [edge.tag for edge in self.pending])
        self.assertEqual(published, [edge.tag for edge in self.pending])
        self.assertIsNone(stopped)
        self.assertEqual([row[0] for row in store.log], ["published"] * 4)
        # Each entry's predecessor is the previous entry: the chain the
        # publisher walks is the chain `binding` re-derives from the ledger.
        with ledger_patch():
            R.binding(ROOT, bound(), R.canonical(selected))

    def test_the_first_refusal_stops_the_run_and_leaves_later_edges_untouched(self):
        for index in range(4):
            tag = self.pending[index].tag
            store = self.Store(LEDGER, self.published)
            _selected, published, stopped = self.drain(
                store, refusals={tag: "identity asset upload returned HTTP 502"})
            with self.subTest(stop=tag):
                self.assertEqual(published, [edge.tag for edge in self.pending[:index]])
                self.assertEqual(stopped[0], tag)
                self.assertIn("HTTP 502", stopped[1])
                self.assertNotIn(tag, store.released)
                for later in self.pending[index + 1:]:
                    self.assertNotIn(later.tag, [row[1] for row in store.log])

    def test_a_zero_asset_draft_resumes_and_a_partial_draft_holds(self):
        store = self.Store(LEDGER, self.published)
        tag = self.pending[0].tag
        _selected, published, stopped = self.drain(store, drafts={tag: 0})
        self.assertEqual(published, [])
        self.assertEqual(stopped[0], tag)
        self.assertEqual(store.drafts, {tag: 0})
        # A fresh dispatch selects the same backlog and the resumed edge
        # publishes; nothing about the selection had to change.
        resumed = self.prepare(store)
        self.assertEqual([entry["tag"] for entry in resumed["edges"]],
                         [edge.tag for edge in self.pending])
        store.publish(tag)
        self.assertIn(tag, store.released)
        partial = self.Store(LEDGER, self.published)
        _selected, published, stopped = self.drain(partial, drafts={tag: 1})
        self.assertEqual(published, [])
        self.assertEqual(partial.drafts, {tag: 1})
        self.assertIn("remains held", stopped[1])

    def test_a_release_with_foreign_asset_names_between_edges_is_refused(self):
        store = self.Store(LEDGER, self.published)
        selected = self.prepare(store)
        value = v4.evidence()
        identity, bundle, release, runs = v4.records(value)
        release["assets"][0]["name"] = "foreign.json"
        api = API({f"/git/ref/tags/{selected['edges'][0]['tag']}":
                   {"ref": "refs/tags/x", "object": {"type": "tag", "sha": "b" * 40}},
                   f"/releases/tags/{selected['edges'][0]['tag']}": release})
        with mock.patch.object(R, "prove_tag", return_value="b" * 40), \
                mock.patch.object(R.C, "_git", return_value=TREE), \
                self.assertRaisesRegex(ValueError, "foreign identity asset names"):
            R.prove_release(ROOT, api, selected["edges"][0]["tag"],
                            selected["edges"][0]["source_sha"])


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

    @staticmethod
    def window_for(value):
        tag = value["tag"]["name"]
        return R.C.TransitionWindow(
            value["predecessor"]["peeled_commit"], value["predecessor"]["tag"],
            R.C.Intent(value["source"]["merge_sha"], R.C.Version.parse(tag.removeprefix("v"))),
            value["changelog"]["fragment_path"], value["changelog"]["fragment_sha256"][7:])

    def prove(self, value, api, *, fetched_tag=None, window=None):
        def git(_root, *args):
            if args[0] == "show":
                return "2026-09-11T00:00:00+00:00"
            if args[-1].startswith("refs/tags/"):
                return fetched_tag or value["tag"]["object_sha"]
            return value["source"]["tree_sha"]
        with mock.patch.object(R.C, "_git", side_effect=git), \
                mock.patch.object(R.C, "_identity_executor_descends", return_value=True), \
                mock.patch.object(R.C, "discover_transition_window",
                                  return_value=window or self.window_for(value)):
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

    def test_a_published_identity_must_match_the_derived_ledger(self):
        """What the retired table pinned for thirteen edges, derived for all.

        The fragment path, its SHA-256 and the predecessor were transcribed
        rows; they are now the ledger's answer at that source, and a published
        identity that disagrees with it is refused here.
        """
        value, api = self.packet()
        with mock.patch.object(R, "verify_signature"):
            self.assertTrue(self.prove(value, api))
        window = self.window_for(value)
        for name, replacement in (
            ("fragment path", R.C.TransitionWindow(window.base_sha, window.base_tag, window.intent,
                                                   "changelog.d/1-foreign.md", window.fragment_sha256)),
            ("fragment digest", R.C.TransitionWindow(window.base_sha, window.base_tag, window.intent,
                                                     window.fragment_path, "0" * 64)),
            ("predecessor sha", R.C.TransitionWindow("a" * 40, window.base_tag, window.intent,
                                                     window.fragment_path, window.fragment_sha256)),
            ("predecessor tag", R.C.TransitionWindow(window.base_sha, "v0.1.79", window.intent,
                                                     window.fragment_path, window.fragment_sha256)),
            ("edge tag", R.C.TransitionWindow(window.base_sha, window.base_tag,
                                              R.C.Intent(window.intent.source_sha, R.C.Version(0, 1, 99)),
                                              window.fragment_path, window.fragment_sha256)),
        ):
            value, api = self.packet()
            with self.subTest(change=name), mock.patch.object(R, "verify_signature"), \
                    self.assertRaises(ValueError):
                self.prove(value, api, window=replacement)

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
        value = v4.evidence()
        tag = value["tag"]["name"]
        for change in ("partial", "oversize", "target", "tag", "immutable"):
            value, api = self.packet()
            release = api.records[f"/releases/tags/{tag}"]
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

    def test_release_present_refuses_a_draft_and_reports_absence(self):
        tag = v4.RECOVERY_TAG
        self.assertTrue(R.release_present(API({f"/releases/tags/{tag}": {"draft": False}}), tag))
        self.assertFalse(R.release_present(API({f"/releases/tags/{tag}": None}), tag))
        with self.assertRaisesRegex(ValueError, "draft Release"):
            R.release_present(API({f"/releases/tags/{tag}": {"draft": True}}), tag)

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
        for status in R.IN_FLIGHT:
            value, api = self.packet()
            api.records["/actions/runs/500/attempts/1"].update(status=status, conclusion=None)
            with self.subTest(status=status), mock.patch.object(R, "verify_signature"), self.assertRaises(R.C.PendingRelease):
                self.prove(value, api)
            for key, replacement in (("id", 501), ("conclusion", "failure")):
                changed = copy.deepcopy(api.records)
                changed["/actions/runs/500/attempts/1"][key] = replacement
                with mock.patch.object(R, "verify_signature"), self.assertRaises(R.C.ContractError) as raised:
                    self.prove(value, API(changed, api.assets))
                self.assertNotIsInstance(raised.exception, R.C.PendingRelease)

    def test_inventory_shape_names_sizes_refuse_before_any_asset_read(self):
        tag = v4.evidence()["tag"]["name"]
        for change in ("tuple", "three", "duplicate", "foreign", "non-object", "bool-size", "float-size"):
            value, api = self.packet()
            release = api.records[f"/releases/tags/{tag}"]
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
        self.assertEqual(R.MAX_JSON, 2097152)

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
        api.requests = api.max_reads
        with self.assertRaisesRegex(ValueError, "read budget"):
            api.get("/required")
        api.requests = 0
        api.deadline = 0
        with self.assertRaisesRegex(ValueError, "read budget"):
            api.get("/required")

    def test_the_cap_widens_with_the_backlog_and_never_shrinks(self):
        api = R.PublicAPI(None)
        self.assertEqual(api.max_reads, R.per_run_bounds(1)[0])
        api.widen(4)
        self.assertEqual(api.max_reads, R.per_run_bounds(4)[0])
        with self.assertRaisesRegex(ValueError, "only widen"):
            api.widen(1)


class RecoveryReadBudgetTests(unittest.TestCase):
    """A2(ii): the per-run cost follows the BACKLOG, never history.

    These tests count requests, so the proofs each request feeds are stubbed;
    the batteries above own those. What stays real is the call graph and the
    shipped reader: every walk here runs through `PublicAPI`, so the bound it
    meets is the production one.
    """

    INSTANT = "2026-09-11T00:00:00+00:00"
    EXECUTOR_MAIN = 400
    EXECUTOR_CODEQL = 401

    class Transport:
        """Serves one fixture to the production reader and counts every GET."""

        def __init__(self):
            self.records = {}
            self.assets = {}
            self.objects = {}
            self.calls = []

        def open(self, request, timeout=None):
            path = request.full_url.removeprefix(R.API)
            self.calls.append(path)
            if path in self.assets:
                return self.body(self.assets[path])
            if path not in self.records:
                raise AssertionError("unexpected API read " + path)
            value = self.records[path]
            if value is None:
                raise urllib.error.HTTPError("", 404, "absent", {}, None)
            return self.body(json.dumps(value).encode())

        @staticmethod
        def body(data):
            value = io.BytesIO(data)
            value.status = 200
            return value

    def fixture(self, published, ledger=LEDGER):
        """Records for a walk whose first `published` ledger edges are complete."""
        transport = self.Transport()
        records, assets = transport.records, transport.assets

        def attempt(run_id, source=SOURCE, tree=TREE, workflow="pull-request.yml"):
            records[f"/actions/runs/{run_id}/attempts/1"] = run(run_id, 1, source, tree, workflow)

        def prepared(tag, source, object_sha):
            transport.objects[tag] = object_sha
            records[f"/git/ref/tags/{tag}"] = {"ref": f"refs/tags/{tag}",
                                               "object": {"type": "tag", "sha": object_sha}}
            records[f"/git/tags/{object_sha}"] = {
                "sha": object_sha, "tag": tag, "object": {"type": "commit", "sha": source},
                "message": f"Platform release {tag} from {source}",
                "tagger": {"name": R.C.RELEASE_TAGGER_NAME,
                           "email": R.C.RELEASE_TAGGER_EMAIL, "date": self.INSTANT}}
            records[f"/releases/tags/{tag}"] = None

        def complete(tag, source, object_sha, release_id, main, publisher, executor):
            prepared(tag, source, object_sha)
            selected = R.E.identity(tag)
            edge = next((item for item in ledger if item.source_sha == source), None)
            value = {"main_ci": {"run_id": main, "run_attempt": 1},
                     "platform_release": {"run_id": publisher, "run_attempt": 1},
                     "source": {"merge_sha": source}}
            if edge is not None:
                value["changelog"] = {"fragment_path": edge.fragment_path,
                                      "fragment_sha256": "sha256:" + edge.fragment_sha256}
                value["predecessor"] = {"tag": edge.base_tag, "peeled_commit": edge.base_sha}
            attempt(main, source, workflow="pull-request.yml")
            attempt(publisher, source, workflow="platform-release.yml")
            if executor is not None:
                value["execution"] = {"source_sha": SOURCE, "main_ci": {"run_id": executor, "run_attempt": 1}}
                attempt(executor, workflow="pull-request.yml")
            identity = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            bundle = b'{"synthetic":"bundle"}\n'
            records[f"/releases/tags/{tag}"] = {"id": release_id, "draft": False, "assets": [
                {"id": release_id + 1, "name": selected["asset"], "size": len(identity)},
                {"id": release_id + 2, "name": selected["bundle"], "size": len(bundle)}]}
            assets[f"/releases/assets/{release_id + 1}"] = identity
            assets[f"/releases/assets/{release_id + 2}"] = bundle

        records[""] = copy.deepcopy(REPOSITORY)
        records["/git/ref/heads/main"] = {"ref": "refs/heads/main",
                                          "object": {"type": "commit", "sha": SOURCE}}
        records["/actions/workflows/platform-release.yml/runs?branch=main&per_page=1"] = {
            "total_count": 0, "workflow_runs": []}
        attempt(500, workflow="platform-release-recovery.yml")
        for workflow, run_id in (("pull-request.yml", self.EXECUTOR_MAIN),
                                 ("codeql.yml", self.EXECUTOR_CODEQL)):
            records[f"/actions/workflows/{workflow}/runs?branch=main&event=push"
                    f"&head_sha={SOURCE}&per_page=100"] = {
                        "total_count": 1, "workflow_runs": [run(run_id, workflow=workflow)]}
            attempt(run_id, workflow=workflow)
            records[f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100"] = {"jobs": []}
        complete(R.E.TERMINAL_V3_TAG, R.E.TERMINAL_V3_SOURCE, R.TERMINAL_TAG_OBJECT,
                 R.TERMINAL_RELEASE_ID, R.TERMINAL_MAIN_RUN, R.TERMINAL_PUBLISHER_RUN, None)
        for index, edge in enumerate(ledger):
            for run_id, workflow in ((600 + index, "pull-request.yml"), (700 + index, "codeql.yml")):
                records[f"/actions/workflows/{workflow}/runs?branch=main&event=push"
                        f"&head_sha={edge.source_sha}&per_page=100"] = {
                            "total_count": 1,
                            "workflow_runs": [run(run_id, source=edge.source_sha,
                                                  tree=edge.tree_sha, workflow=workflow)]}
                attempt(run_id, edge.source_sha, edge.tree_sha, workflow)
                records[f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100"] = {"jobs": []}
            if index < published:
                complete(edge.tag, edge.source_sha, "%040x" % (index + 1), 900 + 4 * index,
                         1600 + index, 1700 + index, 1800 + index)
            else:
                prepared(edge.tag, edge.source_sha, "%040x" % (index + 1))
        return transport

    def walk(self, published, ledger=LEDGER):
        """One `prepare` selection over that fixture; returns its request count."""
        api = R.PublicAPI(None)
        api.opener = self.fixture(published, ledger)

        def git(_root, *args):
            if args[0] == "show":
                return self.INSTANT
            if args[-1].startswith("refs/tags/"):
                return api.opener.objects[args[-1].removeprefix("refs/tags/")]
            return TREE

        real_git = R.C._git
        with mock.patch.multiple(R, prove_trees=mock.DEFAULT, verify_signature=mock.DEFAULT), \
                mock.patch.object(B, "published_edges", return_value=ledger), \
                mock.patch.multiple(
                    R.C, validate_tag_record=mock.DEFAULT,
                    validate_identity_release_record=mock.DEFAULT,
                    validate_identity_run_records=mock.DEFAULT,
                    build_main_ci_jobs_receipt=mock.DEFAULT,
                    _identity_executor_descends=mock.Mock(return_value=True),
                    _git=mock.Mock(side_effect=git),
                    discover_transition_window=mock.Mock(
                        side_effect=lambda _root, source: next(
                            R.C.TransitionWindow(edge.base_sha, edge.base_tag,
                                                 R.C.Intent(edge.source_sha,
                                                            R.C.Version.parse(edge.tag.removeprefix("v"))),
                                                 edge.fragment_path, edge.fragment_sha256)
                            for edge in ledger if edge.source_sha == source)),
                    plan_workflow_run=mock.Mock(
                        side_effect=lambda packet, _name: packet["workflow_run"]["head_sha"]),
                    classify_codeql_run=mock.Mock(
                        side_effect=lambda listing, _source: (listing["workflow_runs"][0]["id"],
                                                              listing["workflow_runs"][0]["run_attempt"]))):
            del real_git
            if published >= len(ledger):
                with self.assertRaisesRegex(ValueError, "backlog is complete"):
                    R.selection(ROOT, api, bound(), stream=io.StringIO())
            else:
                value = R.selection(ROOT, api, bound(), stream=io.StringIO())
                self.assertEqual([entry["tag"] for entry in value["edges"]],
                                 [edge.tag for edge in ledger[published:]])
        self.assertEqual(api.requests, len(api.opener.calls))
        return api.requests

    def test_reads_track_the_backlog_and_not_the_published_history(self):
        """The outage class, replayed: history no longer enters the cost.

        A window of thirteen published edges plus one pending costs exactly
        what one published edge plus one pending costs. Under the retired
        reader the first number grew with every release until the 240 s
        deadline ran out (issue #393).
        """
        long_history = self.walk(len(LEDGER) - 1)
        short_history = self.walk(1, LEDGER[:2])
        self.assertEqual(len(LEDGER), 13)
        self.assertEqual(long_history, short_history)
        # And both sit inside the bound one pending edge derives, which the
        # retired reader could only have met for a one-edge HISTORY.
        self.assertLessEqual(long_history, R.per_run_bounds(1)[0])

    def test_the_per_edge_and_fixed_costs_are_measured_from_the_walk(self):
        counts = [self.walk(len(LEDGER) - pending) for pending in (1, 2, 3, 4)]
        self.assertEqual({later - earlier for earlier, later in zip(counts, counts[1:])},
                         {R.READ_PER_EDGE})
        self.assertLessEqual(R.READ_FIXED, counts[0])
        self.assertLessEqual(counts[0], R.READ_FIXED + R.READ_PER_EDGE)
        for pending, count in zip((1, 2, 3, 4), counts):
            self.assertLessEqual(count, R.READ_FIXED + R.READ_PER_EDGE * pending)
            self.assertGreaterEqual(R.per_run_bounds(pending)[0] * 100,
                                    count * (100 + R.HEADROOM_PERCENT))
        self.assertGreaterEqual(R.HEADROOM_PERCENT, 25)

    def test_the_cap_refuses_the_read_past_it_and_admits_the_one_before(self):
        api = R.PublicAPI(None)
        api.opener = mock.Mock()
        api.opener.open.side_effect = lambda *_args, **_kwargs: self.Transport.body(b"{}")
        api.requests = api.max_reads - 1
        self.assertEqual(api.get("/required"), {})
        self.assertEqual(api.requests, api.max_reads)
        with self.assertRaisesRegex(ValueError, "read budget exhausted"):
            api.get("/required")

    def test_the_deadline_and_the_publish_timeout_are_derived_together(self):
        self.assertEqual((R.DEADLINE_SECONDS, R.EDGE_SECONDS), (240, 4))
        self.assertEqual(R.per_run_bounds(46)[1], R.DEADLINE_SECONDS)
        with self.assertRaisesRegex(ValueError, "inside the recovery deadline"):
            R.per_run_bounds(47)
        self.assertEqual(R.max_pending_edges(), 46)
        self.assertEqual(R.publish_timeout_minutes(),
                         R.PUBLISH_FIXED_MINUTES + R.PUBLISH_EDGE_MINUTES * 46)
        for pending in (0, -1, True, 13.0, "13", None):
            with self.subTest(pending=pending), self.assertRaisesRegex(ValueError, "nonempty backlog"):
                R.per_run_bounds(pending)


class RecoveryCLITests(unittest.TestCase):
    def selected(self):
        return selection_of(LEDGER[-2:])

    def test_bind_rechecks_context_trees_receipt_and_every_publisher_field(self):
        value = self.selected()
        entry = value["edges"][0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(path),
                   "RECOVERY_SELECTION": R.canonical(value),
                   "RECOVERY_EDGE_TAG": entry["tag"],
                   **{key.upper(): entry[key] for key in ("source_sha", "tag", "base_sha", "base_tag")},
                   "MAIN_RUN_ID": str(entry["main_run_id"]), "MAIN_RUN_ATTEMPT": "1",
                   "EXECUTION_MAIN_RUN_ID": "400", "EXECUTION_MAIN_RUN_ATTEMPT": "1"}
            cases = [{}, *({key: "wrong"} for key in ("SOURCE_SHA", "TAG", "BASE_SHA", "BASE_TAG",
                                                      "MAIN_RUN_ID", "MAIN_RUN_ATTEMPT",
                                                      "EXECUTION_MAIN_RUN_ID", "EXECUTION_MAIN_RUN_ATTEMPT",
                                                      "RECOVERY_EDGE_TAG")),
                     {"GITHUB_RUN_ID": "501"},
                     {"RECOVERY_SELECTION": R.canonical({**value, "run_id": 501})}]
            for change in cases:
                with self.subTest(change=change), mock.patch.dict(os.environ, {**env, **change}, clear=True), \
                        ledger_patch(), \
                        mock.patch.object(R, "prove_trees") as trees, mock.patch.object(R, "PublicAPI") as api, \
                        mock.patch("sys.stderr", new_callable=io.StringIO), \
                        mock.patch("sys.stdout", new_callable=io.StringIO):
                    self.assertEqual(R.main(["bind"]), 1 if change else 0)
                    trees.assert_called_once()
                    api.assert_not_called()

    def test_readback_proves_the_published_edge_independently(self):
        value = self.selected()
        entry = value["edges"][0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(path),
                   "RECOVERY_SELECTION": R.canonical(value),
                   "RECOVERY_EDGE_TAG": entry["tag"],
                   "RECOVERY_READ_TOKEN": "synthetic-read-value"}
            for outcome, code in ((True, 0), (False, 1)):
                with self.subTest(outcome=outcome), mock.patch.dict(os.environ, env, clear=True), \
                        ledger_patch(), mock.patch.object(R, "prove_trees"), \
                        mock.patch.object(R, "prove_release", return_value=outcome) as prove, \
                        mock.patch.object(R, "PublicAPI", return_value=API()), \
                        mock.patch("sys.stderr", new_callable=io.StringIO), \
                        mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(R.main(["readback"]), code)
                    self.assertEqual(prove.call_args.args[2:], (entry["tag"], entry["source_sha"]))
                    if outcome:
                        self.assertIn("RECOVERY_READBACK=PASS", out.getvalue())
            with mock.patch.dict(os.environ, {**env, "RECOVERY_EDGE_TAG": "v9.9.9"}, clear=True), \
                    ledger_patch(), \
                    mock.patch.object(R, "prove_trees"), mock.patch.object(R, "prove_release") as prove, \
                    mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(R.main(["readback"]), 1)
                prove.assert_not_called()

    def test_predecessor_cli_preserves_pending_failure_and_no_credential_inheritance(self):
        window = R.C.TransitionWindow(
            R.E.TERMINAL_V3_SOURCE, R.E.TERMINAL_V3_TAG,
            R.C.Intent(LEDGER[0].source_sha, R.C.Version(0, 1, 81)),
            LEDGER[0].fragment_path, LEDGER[0].fragment_sha256)
        env = {"GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "snaraj/platform",
               "GITHUB_REPOSITORY_ID": "1327645656", "SOURCE_SHA": SOURCE,
               "RECOVERY_READ_TOKEN": "synthetic-read-value"}
        for outcome, code in ((True, 0), (False, 1), (R.C.PendingRelease("original pending"), 3),
                              (R.C.ContractError("original failed"), 1)):
            options = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with self.subTest(outcome=outcome), mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(R.C, "discover_transition_window", return_value=window), \
                    mock.patch.object(R, "prove_release", **options) as prove, mock.patch.object(R, "PublicAPI") as api, \
                    mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(R.main(["predecessor"]), code)
                self.assertNotIn("RECOVERY_READ_TOKEN", os.environ)
                api.assert_called_once_with("synthetic-read-value")
                self.assertEqual(prove.call_args.args[-2:], (R.E.TERMINAL_V3_TAG, R.E.TERMINAL_V3_SOURCE))
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
            value = {**self.selected(), "padding": "x" * R.selection_bytes(len(LEDGER))}
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
            value = self.selected()
            for command in ("prepare", "verify"):
                selected = {**env, **({"RECOVERY_SELECTION": R.canonical(value)} if command == "verify" else {})}
                with self.subTest(command=command), mock.patch.dict(os.environ, selected, clear=True), \
                        mock.patch.object(R, "selection", return_value=value) as selection, \
                        mock.patch.object(R, "PublicAPI") as api, mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    self.assertEqual(R.main([command]), 0)
                    self.assertNotIn("RECOVERY_READ_TOKEN", os.environ)
                    self.assertEqual(api.call_args.args, ("synthetic-read-value",))
                    self.assertEqual(api.call_args.kwargs["pending"], 1 if command == "prepare" else 2)
                    self.assertEqual(selection.call_args.args[-1],
                                     R.canonical(value) if command == "verify" else None)
                    self.assertNotIn("synthetic-read-value", stdout.getvalue())
            written = output.read_text()
            self.assertEqual(written.count("selection="), 1)
            self.assertIn("pending=2", written)
            self.assertIn(value["edges"][0]["source_sha"], written)

    def test_cli_refuses_ambient_credentials_bad_mode_and_oversize_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(path), "GITHUB_OUTPUT": str(Path(directory) / "outputs")}
            cases = [{name: "synthetic"} for name in ("GH_TOKEN", "GITHUB_TOKEN", "IMMUTABLE_SETTINGS_TOKEN",
                "ACTIONS_READ_TOKEN", "CONTENTS_READ_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")]
            cases.extend([{"RECOVERY_SELECTION": R.canonical(self.selected())}, {"GITHUB_RUN_ATTEMPT": "2"}])
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
            R.verify_signature(identity, bundle, value["tag"]["name"])
            arguments = execute.call_args.args[0]
            for flag, expected in (("--certificate-identity", "https://github.com/snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main"),
                                   ("--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"),
                                   ("--certificate-github-workflow-sha", value["execution"]["source_sha"]),
                                   ("--certificate-github-workflow-trigger", "workflow_dispatch"), ("--timeout", "30s")):
                self.assertEqual(arguments[arguments.index(flag) + 1], expected)
            self.assertTrue(execute.call_args.kwargs["check"])
            self.assertLessEqual(execute.call_args.kwargs["timeout"], 40)
            self.assertFalse(Path(arguments[-1]).exists())
        ordinary = v4.evidence(False)
        identity, bundle, _, _ = v4.records(ordinary)
        with mock.patch.object(R.subprocess, "run") as execute:
            R.verify_signature(identity, bundle, ordinary["tag"]["name"])
            arguments = execute.call_args.args[0]
            self.assertEqual(arguments[arguments.index("--certificate-identity") + 1],
                             "https://github.com/snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main")
            self.assertEqual(arguments[arguments.index("--certificate-github-workflow-trigger") + 1],
                             "workflow_run")


if __name__ == "__main__":
    unittest.main()
