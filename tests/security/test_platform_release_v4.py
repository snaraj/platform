"""Source and executor are separate facts in the finite publication recovery."""

import copy
import hashlib
import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script
from . import test_platform_release_identity_asset as asset_fixtures

ROOT = Path(__file__).resolve().parents[2]
C = load_script("ci/platform_release_contract.py", module_name="release_v4_contract")
E = C.EPOCH
EPOCH_SCRIPT = ROOT / "scripts/ci/platform_release_epoch.py"
EXECUTOR = "e" * 40
EXECUTOR_TREE = "f" * 40
# v0.1.81 is the first frozen edge whose published identity records an executor
# the window later froze as a source, so its fixtures must carry the pinned
# fact rather than a synthetic executor: with the pin in force nothing else
# validates for that tag (issue #391).
PINNED_TAG = "v0.1.81"
PINNED_EXECUTOR = E.PINNED_EXECUTIONS[PINNED_TAG]["executor_sha"]
PINNED_RELEASE_ID = E.PINNED_EXECUTIONS[PINNED_TAG]["release_id"]
FIXTURE_DIRECTORY = Path(__file__).resolve().parent / "fixtures_release_identity"
IDENTITY_FIXTURE = FIXTURE_DIRECTORY / "v0.1.81-platform-release-identity.v4.json"
# Every frozen edge whose Release exists, with the digest its REST record
# reports for the immutable identity asset committed beside this file. The
# digests are the control: they are what makes an edited fixture fail before it
# can prove anything, and they are transcribed in PROVENANCE.md too.
PUBLISHED_IDENTITIES = {
    "v0.1.81": "4e9cfb1bdbdd27cf8fac42905f5832e3f24a5a24fe2c6636cf63cdabb95db119",
    "v0.1.82": "dab21ffeddb00f7220752f69cc11e4f9154e4fbe85c430fafcaac53020647948",
    "v0.1.83": "6b19aeeadd85e3ade3dc1a6c2f6eab1377d540708ec8862a890a4102476a5474",
    "v0.1.84": "dead16cd692680fdeb32bcd921e1de0b5045e195a414fec4e9f3cb89e87c61b2",
    "v0.1.85": "fd8835b2e140b41c11c0e4b2069b2ce2dc98de9b680579201aaa663850bc8d26",
    "v0.1.86": "d807ca4563da58aae418b9d77feadbd0de175f7c84de92852f6d3d651002682b",
    "v0.1.87": "6bdff5fd75b17a4c13a5f6c40fb8c6df4cc048c95b89d0254ccd337c5b0576c8",
    "v0.1.88": "0d227c2f716038e46c29e6dce1234ff1968406fcb6fa6b34816de5369434da73",
    "v0.1.89": "4f2c87a4b0ee0f4095451be19453b4bec2b8046da2406249ffab923c01d4b723",
}
# Derived from the frozen window's own length so the fixtures follow it when a
# reviewed edge is added, rather than silently testing an already-frozen tag as
# if it were still ordinary.
FROZEN_TAGS = tuple(
    f"v0.1.{81 + index}" for index in range(len(E.HISTORICAL_RELEASES))
)
LAST_FROZEN_TAG = FROZEN_TAGS[-1]
FIRST_ORDINARY_V4_TAG = E.next_tag(LAST_FROZEN_TAG)
# The first frozen edge no publisher has taken yet, so a test that needs an
# UNPINNED edge names one by the table rather than by a hard-coded index that
# the next drain would quietly turn into a pinned one.
FIRST_UNPINNED_INDEX = next(index for index, tag in enumerate(FROZEN_TAGS)
                            if tag not in E.PINNED_EXECUTIONS)
# Imports the file named by argv[1] and reports which of the two things
# happened: the import itself refused, or it succeeded and a production entry
# point answered. Nothing here calls validate_window, so a refusal can only
# come from the module-level call the epoch script makes for itself.
IMPORT_PROBE = """\
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("epoch_under_probe", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
except ValueError as error:
    print("REFUSED " + str(error))
else:
    print("IMPORTED " + module.release_target(sys.argv[2], sys.argv[3]))
"""


def main_ci(source, run_id):
    return {"event": "push", "head_sha": source, "ref": "refs/heads/main",
            "run_id": run_id, "run_attempt": 1, "conclusion": "success",
            "workflow": ".github/workflows/pull-request.yml"}


def evidence(recovering=True):
    frozen = E.HISTORICAL_RELEASES[0]
    source = frozen["source_sha"] if recovering else EXECUTOR
    tree = frozen["tree_sha"] if recovering else EXECUTOR_TREE
    tag = PINNED_TAG if recovering else FIRST_ORDINARY_V4_TAG
    executor = PINNED_EXECUTOR if recovering else EXECUTOR
    release_id = PINNED_RELEASE_ID if recovering else 300
    original_ci = main_ci(source, frozen["main_run_id"] if recovering else 400)
    return {
        "schema": "https://snaraj.dev/schemas/platform-release-identity/v4",
        "repository": "snaraj/platform", "repository_id": 1327645656,
        "source": {"merge_sha": source, "tree_sha": tree, "protected_ref": "refs/heads/main"},
        "tag": {"name": tag, "object_sha": "b" * 40, "object_type": "tag", "peeled_commit": source},
        "predecessor": {"tag": "v0.1.80" if recovering else LAST_FROZEN_TAG,
                        "peeled_commit": frozen["parent_sha"] if recovering else E.HISTORICAL_RELEASES[-1]["source_sha"]},
        "changelog": {"fragment_path": frozen["fragment_path"] if recovering else "changelog.d/1-example.md",
                      "fragment_sha256": "sha256:" + (frozen["fragment_sha256"] if recovering else "a" * 64)},
        "release": {"id": release_id, "asset_count": 2, "draft": False, "immutable": True,
                    "prerelease": False, "tag_name": tag, "target_commitish": "main" if recovering else source},
        "main_ci": original_ci,
        "execution": {"source_sha": executor, "tree_sha": EXECUTOR_TREE, "main_ci": main_ci(executor, 400)},
        "platform_release": {
            "event": "workflow_dispatch" if recovering else "workflow_run", "head_sha": executor,
            "ref": "refs/heads/main", "run_id": 500, "run_attempt": 1,
            "workflow": ".github/workflows/platform-release-recovery.yml" if recovering else ".github/workflows/platform-release.yml",
        },
    }


def records(value):
    canonical = asset_fixtures.PlatformReleaseIdentityAssetTests.canonical(value)
    bundle = asset_fixtures.PlatformReleaseIdentityAssetTests.bundle(canonical)
    tag = value["tag"]["name"]
    assets = []
    version = value["schema"].rsplit("/", 1)[1]
    for number, name, raw in ((900, f"platform-release-identity.{version}.json", canonical),
                              (901, f"platform-release-identity.{version}.json.sigstore.json", bundle)):
        assets.append({"id": number, "name": name, "label": None, "state": "uploaded",
                       "content_type": "application/json", "size": len(raw),
                       "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                       "url": f"https://api.github.com/repos/snaraj/platform/releases/assets/{number}",
                       "browser_download_url": f"https://github.com/snaraj/platform/releases/download/{tag}/{name}",
                       "download_count": 0, "uploader": {"login": "github-actions[bot]", "id": 41898282}})
    release = {**value["release"], "name": "Platform " + tag, "body": "Informational notes",
               "author": {"login": "github-actions[bot]", "id": 41898282}, "assets": assets}
    release.pop("asset_count")
    runs = []
    execution = value.get("execution", {})
    tuples = [(value["main_ci"], value["source"]["tree_sha"]),
              (value["platform_release"], execution.get("tree_sha", value["source"]["tree_sha"]))]
    if "execution" in value:
        tuples.append((execution.get("main_ci", main_ci(EXECUTOR, 400)), execution.get("tree_sha", EXECUTOR_TREE)))
    for run, tree in tuples:
        runs.append({"id": run["run_id"], "run_attempt": run["run_attempt"],
                     "event": run["event"], "head_sha": run["head_sha"], "head_branch": "main",
                     "path": run["workflow"], "status": "completed", "conclusion": "success",
                     "repository": {"id": 1327645656, "full_name": "snaraj/platform"},
                     "head_commit": {"id": run["head_sha"], "tree_id": tree}})
    return canonical, bundle, release, runs


def validate(value, *, run_records=True):
    identity, bundle, release, runs = records(value)
    C.validate_identity_release_record(
        release, identity=identity, bundle=bundle, tag=value["tag"]["name"],
        source_sha=value["source"]["merge_sha"], tree_sha=value["source"]["tree_sha"],
        tag_object_sha=value["tag"]["object_sha"], api_repository="snaraj/platform", api_repository_id=1327645656,
    )
    if run_records:
        C.validate_identity_run_records(identity, runs[0], runs[1], execution_main_run_record=runs[2])


class PlatformReleaseV4Tests(unittest.TestCase):
    def staged_recovery(self, token="untagged-" + "a" * 20):
        value = evidence()
        identity, bundle, release, _ = records(value)
        release.update(tag_name=token, draft=True, immutable=False)
        for asset in release["assets"]:
            asset["browser_download_url"] = asset["browser_download_url"].replace("/v0.1.81/", f"/{token}/")
        kwargs = dict(identity=identity, bundle=bundle, tag="v0.1.81",
                      source_sha=value["source"]["merge_sha"], tree_sha=value["source"]["tree_sha"],
                      tag_object_sha=value["tag"]["object_sha"],
                      api_repository="snaraj/platform", api_repository_id=1327645656, staged=True)
        return release, kwargs

    def test_staged_recovery_accepts_bound_temporary_and_canonical_tags(self):
        for token in ("untagged-" + "a" * 20, "untagged-" + "b" * 20):
            release, kwargs = self.staged_recovery(token)
            for tag in (token, "v0.1.81"):
                with self.subTest(token=token, tag=tag):
                    try:
                        C.validate_identity_release_record({**release, "tag_name": tag}, **kwargs)
                    except C.ContractError as error:
                        self.fail(f"bound staged draft refused: {error}")

    def test_staged_recovery_refuses_foreign_record_and_asset_namespaces(self):
        release, kwargs = self.staged_recovery()
        for tag in (None, "v0.1.82", "untagged-" + "b" * 20, "untagged-" + "A" * 20,
                    "untagged-" + "a" * 19, "untagged-" + "a" * 21):
            with self.subTest(tag=tag), self.assertRaises(C.ContractError):
                C.validate_identity_release_record({**release, "tag_name": tag}, **kwargs)
        for indexes in ((0,), (1,), (0, 1)):
            changed = copy.deepcopy(release)
            for index in indexes:
                changed["assets"][index]["browser_download_url"] = changed["assets"][index][
                    "browser_download_url"].replace("untagged-" + "a" * 20, "untagged-" + "b" * 20)
            with self.subTest(assets=indexes), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(changed, **kwargs)
        for token in ("untagged-" + "A" * 20, "untagged-" + "a" * 19, "untagged-" + "a" * 21):
            # A coherent pair must still reject a malformed namespace, without
            # relying on the separate mixed-token guard to catch it.
            changed, kwargs = self.staged_recovery(token)
            with self.subTest(coherent_token=token), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(changed, **kwargs)

    def test_staged_recovery_keeps_lifecycle_custody_and_intended_tag_checks(self):
        release, kwargs = self.staged_recovery()
        for key, value in (("draft", False), ("immutable", True), ("prerelease", True),
                           ("target_commitish", "a" * 40), ("name", "Platform v0.1.82"),
                           ("id", 301), ("author", {"login": "other", "id": 1})):
            with self.subTest(field=key), self.assertRaises(C.ContractError):
                C.validate_identity_release_record({**release, key: value}, **kwargs)
        for key, value in (("source_sha", "a" * 40), ("tag", "v0.1.82"),
                           ("tag_object_sha", "c" * 40), ("tree_sha", "d" * 40)):
            with self.subTest(binding=key), self.assertRaises(C.ContractError):
                C.validate_identity_release_record(release, **{**kwargs, key: value})

    def test_immutable_recovery_refuses_temporary_tag_even_with_matching_asset_urls(self):
        release, kwargs = self.staged_recovery()
        release.update(draft=False, immutable=True)
        # Coherent temporary final URLs pass the metadata projection; the
        # immutable release boundary itself must still reject this tag.
        with self.assertRaisesRegex(C.ContractError, "REST release"):
            C.validate_identity_release_record(release, **{**kwargs, "staged": False})

    def test_recovery_draft_target_custody_and_zero_assets_are_independent(self):
        value = evidence()
        record = {"id": 300, "tag_name": "v0.1.81", "name": "Platform v0.1.81", "target_commitish": "main",
                  "body": "exact marker", "draft": True, "prerelease": False, "immutable": False,
                  "author": {"login": "github-actions[bot]", "id": 41898282}, "assets": []}
        def check(candidate):
            C.validate_draft_release_record(candidate, tag="v0.1.81", source_sha=value["source"]["merge_sha"],
                                             title="Platform v0.1.81", body="exact marker", expected_release_id=300)
        check(record)
        for key, replacement in (("target_commitish", value["source"]["merge_sha"]), ("target_commitish", "master"),
                ("name", "foreign"), ("assets", [{}]), ("id", 301), ("immutable", True),
                ("author", {"login": "other", "id": 1})):
            with self.subTest(field=key), self.assertRaises(C.ContractError):
                check({**record, key: replacement})

    def test_run_record_cli_requires_the_actual_executor_attempt(self):
        raw, _, _, runs = records(evidence())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "identity.json").write_bytes(raw)
            paths = []
            for index, record in enumerate(runs):
                path = root / f"run-{index}.json"
                path.write_text(json.dumps(record))
                paths.append(str(path))
            args = ["contract", "identity-run-records", "--identity", str(root / "identity.json"),
                    "--main-run-json", paths[0], "--platform-run-json", paths[1],
                    "--execution-main-run-json", paths[2]]
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(C.main(), 0)
            runs[2]["id"] = 999
            Path(paths[2]).write_text(json.dumps(runs[2]))
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(C.main(), 1)

    def test_closed_historical_publication_window(self):
        for index, entry in enumerate(E.HISTORICAL_RELEASES):
            tag = f"v0.1.{81 + index}"
            self.assertEqual(E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag,
                             f"v0.1.{80 + index}", entry["parent_sha"], entry["source_sha"])["version"], 4)
            for source, parent in ((None, entry["parent_sha"]), ("a" * 40, entry["parent_sha"]),
                                   (entry["source_sha"], "a" * 40)):
                with self.subTest(source=source, parent=parent), self.assertRaises(ValueError):
                    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag, f"v0.1.{80 + index}", parent, source)
            with self.assertRaises(ValueError):
                E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, FIRST_ORDINARY_V4_TAG,
                              LAST_FROZEN_TAG, "a" * 40, entry["source_sha"])
            with self.assertRaises(ValueError):
                E.release_target(tag, "a" * 40)
        # The recovery run lookup retired with the recovery workflow (issue #397).
        with mock.patch.object(sys, "argv", ["epoch", "v0.1.81", "--historical-main-run"]), \
                mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
            E.main()

    def frozen_evidence(self, index):
        """Evidence for another frozen edge, so the unpinned rule is exercised.

        The generic fixture is v0.1.81, a pinned edge; without an edge that
        carries NO pin the membership refusal could be deleted and still pass.
        """
        frozen = E.HISTORICAL_RELEASES[index]
        tag = f"v0.1.{81 + index}"
        value = evidence()
        value["tag"].update(name=tag, peeled_commit=frozen["source_sha"])
        value["release"].update(id=300 + index, tag_name=tag)
        value["predecessor"] = {"tag": f"v0.1.{80 + index}", "peeled_commit": frozen["parent_sha"]}
        value["source"].update(merge_sha=frozen["source_sha"], tree_sha=frozen["tree_sha"])
        value["changelog"] = {"fragment_path": frozen["fragment_path"],
                              "fragment_sha256": "sha256:" + frozen["fragment_sha256"]}
        value["main_ci"] = main_ci(frozen["source_sha"], frozen["main_run_id"])
        value["execution"] = {"source_sha": EXECUTOR, "tree_sha": EXECUTOR_TREE,
                              "main_ci": main_ci(EXECUTOR, 400)}
        value["platform_release"]["head_sha"] = EXECUTOR
        return value

    def test_a_frozen_pin_is_a_published_fact_and_never_a_forward_allowance(self):
        # Exactly these edges are pinned, at exactly these values. Offline code
        # cannot ask GitHub whether a Release exists, so the reviewed table is
        # the control and this equality is the tripwire on it: an added pin, or
        # a moved one, is a deliberate edit here and in the window fingerprint.
        # One drain by one executor is one block of rows: 10ee0a67 published
        # v0.1.81, and 76f60b30 published v0.1.82 through v0.1.89 before this
        # change froze it as v0.1.93's source.
        self.assertEqual(E.PINNED_EXECUTIONS, {
            "v0.1.81": {"release_id": 387789735,
                        "executor_sha": "10ee0a67144675630456daafeb002755aba653d4"},
            "v0.1.82": {"release_id": 394156049,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.83": {"release_id": 394157866,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.84": {"release_id": 394159524,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.85": {"release_id": 394161048,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.86": {"release_id": 394162468,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.87": {"release_id": 394164673,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.88": {"release_id": 394166552,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
            "v0.1.89": {"release_id": 394168254,
                        "executor_sha": "76f60b306d028f5a2febcbf7b35c8ab16b0dd139"},
        })
        # Every pinned tag is a frozen edge carrying exactly that value, and
        # the entries and the table can never drift apart silently.
        for tag, recorded in E.PINNED_EXECUTIONS.items():
            entry = E.historical_release(tag)
            self.assertIsNotNone(entry)
            self.assertEqual(E.frozen_executor(tag, dict(entry)), recorded["executor_sha"])
        entry = dict(E.HISTORICAL_RELEASES[0])
        self.assertEqual(E.frozen_executor(PINNED_TAG, entry), PINNED_EXECUTOR)
        for change in ({"executor_sha": "a" * 40}, {"executor_sha": PINNED_EXECUTOR.upper()},
                       {"executor_sha": None}, {"executor_sha": 0}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                E.frozen_executor(PINNED_TAG, {**entry, **change})
        with self.assertRaisesRegex(ValueError, "drops its recorded executor pin"):
            E.frozen_executor(PINNED_TAG, {k: v for k, v in entry.items() if k != "executor_sha"})
        for recorded in ({"executor_sha": PINNED_EXECUTOR},
                         {"release_id": True, "executor_sha": PINNED_EXECUTOR},
                         {"release_id": 0, "executor_sha": PINNED_EXECUTOR},
                         {"release_id": PINNED_RELEASE_ID, "executor_sha": PINNED_EXECUTOR, "extra": 1}):
            with self.subTest(recorded=recorded), mock.patch.dict(
                    E.PINNED_EXECUTIONS, {PINNED_TAG: recorded}), self.assertRaises(ValueError):
                E.frozen_executor(PINNED_TAG, entry)
        # The 40-hex shape is checked on the pin itself, not merely implied
        # by a well-formed table: a record and an entry that AGREE on a SHA
        # GitHub could not have recorded still refuse, so a future edit to the
        # reviewed table cannot license one by transcribing it into both.
        for spelling, malformed in (("uppercase", PINNED_EXECUTOR.upper()),
                                    ("truncated", PINNED_EXECUTOR[:-1])):
            with self.subTest(spelling=spelling), mock.patch.dict(
                    E.PINNED_EXECUTIONS,
                    {PINNED_TAG: {"release_id": PINNED_RELEASE_ID, "executor_sha": malformed}}), \
                    self.assertRaisesRegex(ValueError, "no published Release"):
                E.frozen_executor(PINNED_TAG, {**entry, "executor_sha": malformed})
        # Every edge the publisher has not taken yet is unpinned, and a pin
        # cannot be granted to one no published Release records — the
        # thirteenth edge frozen here included.
        unpinned = [index for index, tag in enumerate(FROZEN_TAGS)
                    if tag not in E.PINNED_EXECUTIONS]
        self.assertEqual(unpinned, list(range(len(E.PINNED_EXECUTIONS),
                                              len(E.HISTORICAL_RELEASES))))
        for index in unpinned:
            tag = FROZEN_TAGS[index]
            other = dict(E.HISTORICAL_RELEASES[index])
            self.assertIsNone(E.frozen_executor(tag, other))
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "no published Release"):
                E.frozen_executor(tag, {**other, "executor_sha": PINNED_EXECUTOR})

    def test_the_window_sweep_refuses_an_unbacked_pin_for_every_entry_point(self):
        window = E.HISTORICAL_RELEASES
        E.validate_window()
        cases = {
            "pinned unpublished edge": (*window[:-1], {**window[-1], "executor_sha": PINNED_EXECUTOR}),
            "pin dropped": tuple({k: v for k, v in entry.items() if k != "executor_sha"}
                                 for entry in window),
            "foreign field": ({**window[0], "extra": 1}, *window[1:]),
        }
        for name, mutated in cases.items():
            with self.subTest(case=name), mock.patch.object(E, "HISTORICAL_RELEASES", mutated), \
                    self.assertRaises(ValueError):
                E.validate_window()
        with mock.patch.dict(E.PINNED_EXECUTIONS, {"v0.1.70": {"release_id": 1, "executor_sha": "a" * 40}}), \
                self.assertRaisesRegex(ValueError, "names no frozen edge"):
            E.validate_window()

    def test_the_module_level_sweep_call_is_what_refuses_an_unbacked_pin(self):
        """Prove the wiring, not the helper: delete the call and this goes red.

        Every other check above reaches ``validate_window`` by name, so all of
        them survive disconnecting it from module import — the helper was
        proven and its automatic invocation was not. This test never names it.
        It writes a copy of the script carrying an unbacked pin on the frozen
        edge no publisher has taken yet, then merely IMPORTS that copy in a
        fresh isolated interpreter, so neither this process's already-loaded
        module nor a bytecode cache can answer in its place. A refusal there
        can come from nothing but the module-level call, and the second case
        shows the production command-line entry point refusing for the same
        reason rather than an import in isolation. The unmodified source is the
        positive control: it must import and answer, so a red result is the
        injected pin and never the copying.
        """
        source = EPOCH_SCRIPT.read_text(encoding="utf-8")
        unpublished = E.HISTORICAL_RELEASES[-1]
        anchor = '        "source_sha": "{}",\n'.format(unpublished["source_sha"])
        self.assertEqual(source.count(anchor), 1)
        forward = source.replace(
            anchor, anchor + '        "executor_sha": "{}",\n'.format(PINNED_EXECUTOR))
        self.assertEqual(forward.count("executor_sha"), source.count("executor_sha") + 1)
        refusal = "frozen edge pins an executor no published Release records"
        with tempfile.TemporaryDirectory() as directory:
            imported, command = {}, {}
            for name, text in (("intact", source), ("forward_pin", forward)):
                copy_path = Path(directory) / (name + "_epoch.py")
                copy_path.write_text(text, encoding="utf-8")
                imported[name] = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", IMPORT_PROBE, str(copy_path),
                     PINNED_TAG, E.HISTORICAL_RELEASES[0]["source_sha"]],
                    capture_output=True, text=True, check=False, timeout=60)
                command[name] = subprocess.run(
                    [sys.executable, "-I", "-B", str(copy_path), PINNED_TAG],
                    capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(imported["intact"].returncode, 0, imported["intact"].stderr)
            self.assertEqual(imported["intact"].stdout, "IMPORTED main\n")
            self.assertEqual(command["intact"].returncode, 0, command["intact"].stderr)
            self.assertEqual(json.loads(command["intact"].stdout)["publisher_workflow"],
                             E.RECOVERY_WORKFLOW)
            self.assertEqual(imported["forward_pin"].returncode, 0,
                             imported["forward_pin"].stderr)
            self.assertEqual(imported["forward_pin"].stdout, "REFUSED " + refusal + "\n")
            # The command-line entry point never reaches its own argument
            # parsing, so the refusal is not a caught-and-reported denial.
            self.assertNotEqual(command["forward_pin"].returncode, 0)
            self.assertEqual(command["forward_pin"].stdout, "")
            self.assertIn(refusal, command["forward_pin"].stderr)

    def test_the_published_v0_1_81_identity_validates_only_through_its_pin(self):
        raw = IDENTITY_FIXTURE.read_bytes()
        # The digest the REST record reports for the immutable asset: an edited
        # copy of these bytes fails here before it can prove anything.
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "4e9cfb1bdbdd27cf8fac42905f5832e3f24a5a24fe2c6636cf63cdabb95db119")
        published = json.loads(raw)
        self.assertEqual(published["tag"]["name"], PINNED_TAG)
        self.assertEqual(published["execution"]["source_sha"], PINNED_EXECUTOR)
        self.assertEqual(published["release"]["id"], PINNED_RELEASE_ID)
        E.validate_execution(published)
        unpinned = tuple({k: v for k, v in entry.items() if k != "executor_sha"}
                         for entry in E.HISTORICAL_RELEASES)
        # The rule this change replaces — the same window with no pin — refuses
        # these exact published bytes, because the executor they record became
        # v0.1.91's frozen source. The pinned path is what admits them.
        with mock.patch.object(E, "HISTORICAL_RELEASES", unpinned), \
                mock.patch.dict(E.PINNED_EXECUTIONS, {}, clear=True), \
                self.assertRaisesRegex(ValueError, "historical execution"):
            E.validate_execution(published)
        moved = ({**E.HISTORICAL_RELEASES[0], "executor_sha": "a" * 40}, *E.HISTORICAL_RELEASES[1:])
        with mock.patch.object(E, "HISTORICAL_RELEASES", moved), \
                mock.patch.dict(E.PINNED_EXECUTIONS,
                                {PINNED_TAG: {"release_id": PINNED_RELEASE_ID, "executor_sha": "a" * 40}}), \
                self.assertRaisesRegex(ValueError, "historical execution"):
            E.validate_execution(published)
        # The pin binds the Release that recorded it, not just the SHA.
        with self.assertRaisesRegex(ValueError, "historical execution"):
            E.validate_execution({**published,
                                  "release": {**published["release"], "id": PINNED_RELEASE_ID + 1}})

    def test_every_published_identity_validates_against_this_window(self):
        """The class guard: each published edge's real bytes, at this head.

        The pin repair is per edge, but the defect is per DRAIN — one executor
        publishes many edges, and freezing it later turns the membership
        refusal against every one of them at once (issue #393 found exactly
        that, eight edges deep, after issue #391 pinned only the first). A test
        that names one tag can only ever catch the edge somebody already
        thought about. This one refuses on behalf of the whole class: it walks
        every immutable identity asset committed beside it and puts it through
        the production `validate_execution`, so a future window extension that
        freezes an executor without pinning the edges it published goes red
        here, offline, before anyone dispatches a drain that cannot run.
        """
        self.assertEqual(
            sorted(path.name for path in FIXTURE_DIRECTORY.glob("*.json")),
            sorted(f"{tag}-platform-release-identity.v4.json" for tag in PUBLISHED_IDENTITIES))
        # The published edges are a contiguous prefix of the window: the
        # backlog drains in order, so a gap here means a fixture was forgotten
        # rather than that an edge is genuinely unpublished.
        self.assertEqual(tuple(PUBLISHED_IDENTITIES), FROZEN_TAGS[:len(PUBLISHED_IDENTITIES)])
        for tag, digest in PUBLISHED_IDENTITIES.items():
            with self.subTest(tag=tag):
                raw = (FIXTURE_DIRECTORY / f"{tag}-platform-release-identity.v4.json").read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                published = json.loads(raw)
                self.assertEqual(published["tag"]["name"], tag)
                # The production path, unmocked: repository, epoch, predecessor
                # and the frozen edge's own fields, then the executor rule.
                E.validate_identity(published)
                E.validate_execution(published)
                executor = published["execution"]["source_sha"]
                # Whatever the asset records is what the table records, and
                # only an edge whose executor the window froze needs a pin.
                if executor in {entry["source_sha"] for entry in E.HISTORICAL_RELEASES}:
                    self.assertEqual(E.PINNED_EXECUTIONS[tag],
                                     {"release_id": published["release"]["id"],
                                      "executor_sha": executor})
        # Dropping any single pin puts that one published edge straight back
        # under the membership refusal, with every other pin still in place.
        for tag in E.PINNED_EXECUTIONS:
            raw = (FIXTURE_DIRECTORY / f"{tag}-platform-release-identity.v4.json").read_bytes()
            published = json.loads(raw)
            index = FROZEN_TAGS.index(tag)
            dropped = tuple({k: v for k, v in entry.items() if k != "executor_sha"}
                            if position == index else entry
                            for position, entry in enumerate(E.HISTORICAL_RELEASES))
            table = {key: value for key, value in E.PINNED_EXECUTIONS.items() if key != tag}
            with self.subTest(dropped=tag), \
                    mock.patch.object(E, "HISTORICAL_RELEASES", dropped), \
                    mock.patch.dict(E.PINNED_EXECUTIONS, table, clear=True), \
                    self.assertRaisesRegex(ValueError, "historical execution"):
                E.validate_execution(published)

    def test_execution_semantics_refuse_unknown_fields_and_historical_executors(self):
        exact = evidence()
        changes = [({"extra": True}, "execution"), ({"extra": True}, "main_ci")]
        for extra, field in changes:
            value = copy.deepcopy(exact)
            target = value["execution"] if field == "execution" else value["execution"]["main_ci"]
            target.update(extra)
            with self.subTest(field=field), self.assertRaises(ValueError):
                E.validate_execution(value)
        for replacement in (None, [], "execution"):
            value = copy.deepcopy(exact)
            value["execution"] = replacement
            with self.subTest(shape=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for key, replacement in (("source_sha", None), ("tree_sha", 42), ("main_ci", None),
                                  ("main_ci", [])):
            value = copy.deepcopy(exact)
            value["execution"][key] = replacement
            with self.subTest(field=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for key, replacement in (("conclusion", "failure"), ("event", "workflow_dispatch"),
                ("head_sha", "a" * 40), ("ref", "refs/heads/other"), ("workflow", "foreign.yml"),
                ("run_id", True), ("run_id", 0), ("run_attempt", True), ("run_attempt", 0)):
            value = copy.deepcopy(exact)
            value["execution"]["main_ci"][key] = replacement
            with self.subTest(ci=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value)
        for recovering in (True, False):
            value = evidence(recovering)
            value["source"]["merge_sha"] = "a" * 40
            with self.subTest(source=recovering), self.assertRaises(ValueError):
                E.validate_execution(value)
        # The pinned edge admits exactly the executor its published identity
        # records; the terminal checkpoint and every other frozen source still
        # refuse, so the pin narrows the membership rule rather than relaxing it.
        E.validate_execution(copy.deepcopy(exact))
        for sha in (E.TERMINAL_V3_SOURCE, *(row["source_sha"] for row in E.HISTORICAL_RELEASES)):
            if sha == PINNED_EXECUTOR:
                continue
            value = copy.deepcopy(exact)
            value["execution"]["source_sha"] = sha
            value["execution"]["main_ci"]["head_sha"] = sha
            value["platform_release"]["head_sha"] = sha
            with self.subTest(sha=sha), self.assertRaisesRegex(ValueError, "historical execution"):
                E.validate_execution(value)
        # An UNPINNED frozen edge keeps the untouched membership refusal: a
        # frozen source can never present itself as another edge's executor.
        unpinned = self.frozen_evidence(FIRST_UNPINNED_INDEX)
        E.validate_execution(copy.deepcopy(unpinned))
        for sha in (E.TERMINAL_V3_SOURCE, *(row["source_sha"] for row in E.HISTORICAL_RELEASES)):
            value = copy.deepcopy(unpinned)
            value["execution"]["source_sha"] = sha
            value["execution"]["main_ci"]["head_sha"] = sha
            value["platform_release"]["head_sha"] = sha
            with self.subTest(unpinned=sha), self.assertRaisesRegex(ValueError, "historical execution"):
                E.validate_execution(value)
        for key, replacement in (("tree_sha", "a" * 40), ("main_ci", main_ci(EXECUTOR, 401))):
            value = evidence(False)
            value["execution"][key] = replacement
            with self.subTest(ordinary=key), self.assertRaisesRegex(ValueError, "ordinary publication"):
                E.validate_execution(value)

    def test_policy_preserves_old_epochs_and_closes_recovery_subjects(self):
        for tag, version in (("v0.1.69", 1), ("v0.1.77", 2), ("v0.1.80", 3), ("v0.1.81", 4),
                             (FIRST_ORDINARY_V4_TAG, 4)):
            self.assertEqual(E.identity(tag)["version"], version)
        # The whole frozen window carries the recovery subject, not just its
        # first three edges: issue #317 extended it through v0.1.91, issue
        # #391 froze the twelfth edge, v0.1.92, and issue #393 freezes the
        # thirteenth, v0.1.93.
        self.assertEqual(LAST_FROZEN_TAG, "v0.1.93")
        for tag in FROZEN_TAGS:
            selected = E.identity(tag)
            self.assertEqual(selected["publisher_workflow"], ".github/workflows/platform-release-recovery.yml")
            self.assertEqual(selected["publisher_event"], "workflow_dispatch")
            self.assertEqual(selected["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main")
        self.assertEqual(E.identity(FIRST_ORDINARY_V4_TAG)["publisher_event"], "workflow_run")
        self.assertEqual(E.identity(FIRST_ORDINARY_V4_TAG)["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main")

    def test_historical_and_ordinary_assets_and_actual_run_bindings_pass(self):
        validate(evidence())
        validate(evidence(False))

    def test_recovery_cannot_substitute_source_or_executor_claims(self):
        exact = evidence()
        mutations = [
            (("execution", "source_sha"), "a" * 40),
            (("execution", "tree_sha"), "bad"),
            (("execution", "main_ci", "head_sha"), "a" * 40),
            (("execution", "main_ci", "event"), "workflow_dispatch"),
            (("execution", "main_ci", "workflow"), "foreign.yml"),
            (("execution", "main_ci", "conclusion"), "failure"),
            (("execution", "main_ci", "ref"), "refs/heads/other"),
            (("execution", "main_ci", "run_id"), True),
            (("execution", "main_ci", "run_attempt"), 0),
            (("platform_release", "head_sha"), exact["source"]["merge_sha"]),
            (("platform_release", "event"), "workflow_run"),
            (("platform_release", "workflow"), ".github/workflows/platform-release.yml"),
            (("platform_release", "run_attempt"), 2),
            (("main_ci", "run_id"), 401),
            (("main_ci", "run_attempt"), 2),
            (("source", "tree_sha"), "a" * 40),
            (("changelog", "fragment_sha256"), "sha256:" + "0" * 64),
            (("predecessor", "peeled_commit"), "a" * 40),
        ]
        for path, replacement in mutations:
            changed = copy.deepcopy(exact)
            parent = changed
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises((C.ContractError, ValueError)):
                validate(changed, run_records=False)
        for field in ("source_sha", "tree_sha", "main_ci"):
            changed = copy.deepcopy(exact)
            del changed["execution"][field]
            with self.subTest(missing=field), self.assertRaises(C.ContractError):
                validate(changed)

    def test_ordinary_publication_cannot_claim_a_different_executor(self):
        changed = evidence(False)
        changed["execution"]["source_sha"] = "a" * 40
        changed["execution"]["main_ci"]["head_sha"] = "a" * 40
        changed["platform_release"]["head_sha"] = "a" * 40
        with self.assertRaises(C.ContractError):
            validate(changed)

    def test_original_failed_or_running_attempt_cannot_be_replaced_by_later_success(self):
        identity, _, _, runs = records(evidence())
        for index in (0, 1, 2):
            for field, value in (("conclusion", "failure"), ("conclusion", "cancelled"),
                                 ("status", "in_progress"), ("run_attempt", 2),
                                 ("id", 999), ("head_sha", "a" * 40)):
                changed = copy.deepcopy(runs)
                changed[index][field] = value
                with self.subTest(index=index, field=field, value=value), self.assertRaises(C.ContractError):
                    C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2])
        with self.assertRaisesRegex(C.ContractError, "requires executor main CI proof"):
            C.validate_identity_run_records(identity, runs[0], runs[1])
        for repository_id in (True, 1):
            changed = evidence()
            changed["repository_id"] = repository_id
            raw, _, _, actual = records(changed)
            with self.assertRaisesRegex(C.ContractError, "run identity epoch"):
                C.validate_identity_run_records(raw, *actual[:2], execution_main_run_record=actual[2])
        changed = copy.deepcopy(runs)
        changed[2]["head_commit"]["tree_id"] = "a" * 40
        with self.assertRaises(C.ContractError):
            C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2])

    def test_pending_reader_mode_never_substitutes_original_identity_or_success(self):
        identity, _, _, runs = records(evidence())
        for status in ("queued", "in_progress", "pending", "requested", "waiting"):
            pending = copy.deepcopy(runs)
            pending[1].update(status=status, conclusion=None)
            C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2], platform_pending=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2])
            for row, field, replacement in ((0, "status", "queued"), (2, "status", "queued"),
                    (1, "conclusion", "success"), (1, "conclusion", "failure"), (1, "status", "unknown"),
                    (1, "status", "completed"), (1, "id", 501), (1, "run_attempt", 2), (1, "head_sha", "a" * 40)):
                changed = copy.deepcopy(pending)
                changed[row][field] = replacement
                with self.subTest(status=status, row=row, field=field), self.assertRaises(C.ContractError):
                    C.validate_identity_run_records(identity, *changed[:2], execution_main_run_record=changed[2], platform_pending=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2],
                                                platform_pending=True, platform_conclusion="failure")
        ordinary, _, _, ordinary_runs = records(evidence(False))
        # Equal source/executor may reuse the same exact main record; unlike
        # recovery this path does not require a separately supplied record.
        C.validate_identity_run_records(ordinary, *ordinary_runs[:2])
        legacy = evidence(False)
        del legacy["execution"]
        legacy["schema"] = "https://snaraj.dev/schemas/platform-release-identity/v3"
        legacy["tag"]["name"] = legacy["release"]["tag_name"] = "v0.1.80"
        raw, _, _, prior_runs = records(legacy)
        prior_runs[1].update(status="in_progress", conclusion=None)
        with self.assertRaisesRegex(C.ContractError, "pending publisher classification"):
            C.validate_identity_run_records(raw, *prior_runs, platform_pending=True)
        for path, replacement in (("fragment_path", "changelog.d/1-foreign.md"), ("fragment_sha256", "sha256:" + "0" * 64)):
            value = evidence()
            value["changelog"][path] = replacement
            raw, _, _, changed_runs = records(value)
            with self.assertRaisesRegex(C.ContractError, "signed publication execution"):
                C.validate_identity_run_records(raw, *changed_runs[:2], execution_main_run_record=changed_runs[2])

    def test_default_target_hint_is_exact_and_does_not_replace_the_tag_source(self):
        for target in ("master", EXECUTOR, evidence()["source"]["merge_sha"], "refs/heads/main"):
            changed = evidence()
            changed["release"]["target_commitish"] = target
            with self.subTest(target=target), self.assertRaises(C.ContractError):
                validate(changed)

    def test_renderer_separates_actual_execution_and_preserves_source(self):
        expected = evidence()
        source = expected["source"]["merge_sha"]
        window = C.TransitionWindow(expected["predecessor"]["peeled_commit"], "v0.1.80",
                                    C.Intent(source, C.Version(0, 1, 81)),
                                    expected["changelog"]["fragment_path"], expected["changelog"]["fragment_sha256"][7:])
        def git(_repository, *args):
            return expected["source"]["tree_sha"] if args[-1] == source + "^{tree}" else EXECUTOR_TREE
        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), mock.patch.object(C, "_git", side_effect=git), mock.patch.object(C, "discover_transition_window", return_value=window):
            kwargs = dict(expected_base_sha=window.base_sha, expected_base_tag=window.base_tag,
                tag_object_sha="b" * 40, release_id=PINNED_RELEASE_ID,
                main_run_id=expected["main_ci"]["run_id"],
                main_run_attempt=1, platform_run_id=500, platform_run_attempt=1,
                github_repository="snaraj/platform", github_repository_id=1327645656,
                # The pinned edge renders only its recorded executor and
                # Release; a re-render claiming another one is refused.
                execution_sha=PINNED_EXECUTOR, execution_main_run_id=400, execution_main_run_attempt=1,
            )
            rendered = C.render_release_identity(ROOT, source, PINNED_TAG, **kwargs)
            for change in ({"execution_sha": EXECUTOR}, {"release_id": 300}):
                with self.subTest(pinned=change), self.assertRaisesRegex(C.ContractError, "release identity epoch"):
                    C.render_release_identity(ROOT, source, PINNED_TAG, **{**kwargs, **change})
            for change in ({"github_repository": None, "github_repository_id": None},
                           {"execution_main_run_id": None}, {"execution_main_run_id": True},
                           {"execution_main_run_id": 0}, {"execution_main_run_attempt": None},
                           {"execution_main_run_attempt": True}, {"execution_main_run_attempt": 0}):
                message = "repository" if "github_repository" in change else "executor main CI requires"
                with self.subTest(change=change), self.assertRaisesRegex(C.ContractError, message):
                    C.render_release_identity(ROOT, source, "v0.1.81", **{**kwargs, **change})
        self.assertEqual(json.loads(rendered), expected)
        ordinary = evidence(False)
        window = C.TransitionWindow(
            ordinary["predecessor"]["peeled_commit"], LAST_FROZEN_TAG,
            C.Intent(EXECUTOR, C.Version.parse(FIRST_ORDINARY_V4_TAG.removeprefix("v"))),
            "changelog.d/1-example.md", "a" * 64)
        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), \
                mock.patch.object(C, "_git", return_value=EXECUTOR_TREE), \
                mock.patch.object(C, "discover_transition_window", return_value=window):
            rendered = C.render_release_identity(ROOT, EXECUTOR, FIRST_ORDINARY_V4_TAG,
                expected_base_sha=window.base_sha,
                expected_base_tag=window.base_tag, tag_object_sha="b" * 40, release_id=300,
                main_run_id=400, main_run_attempt=1, platform_run_id=500, platform_run_attempt=1,
                github_repository="snaraj/platform", github_repository_id=1327645656)
        self.assertEqual(json.loads(rendered), ordinary)

    def test_schema_requires_closed_execution_and_only_documented_target_shapes(self):
        schema = json.loads((ROOT / "bootstrap/flux/release-selector/platform-release-identity.v4.schema.json").read_text())
        self.assertEqual(schema["$id"], "https://snaraj.dev/schemas/platform-release-identity/v4")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("execution", schema["required"])
        execution = schema["properties"]["execution"]
        self.assertEqual(execution["type"], "object")
        self.assertEqual(schema["properties"]["schema"], {"const": "https://snaraj.dev/schemas/platform-release-identity/v4"})
        self.assertFalse(execution["additionalProperties"])
        self.assertEqual(set(execution["required"]), {"source_sha", "tree_sha", "main_ci"})
        self.assertEqual(execution["properties"]["main_ci"], {"$ref": "#/properties/main_ci"})
        self.assertEqual(schema["properties"]["release"]["properties"]["target_commitish"], {"oneOf": [{"$ref": "#/$defs/sha"}, {"const": "main"}]})
        self.assertEqual(schema["properties"]["platform_release"]["properties"]["event"],
                         {"enum": ["workflow_run", "workflow_dispatch"]})
        self.assertEqual(schema["properties"]["platform_release"]["properties"]["workflow"],
                         {"enum": [".github/workflows/platform-release.yml", ".github/workflows/platform-release-recovery.yml"]})
        self.assertEqual(execution["properties"]["source_sha"], {"$ref": "#/$defs/sha"})
        self.assertEqual(execution["properties"]["tree_sha"], {"$ref": "#/$defs/sha"})
        # All old schema requirements carry forward unchanged except these
        # explicit source/executor additions. No inherited field becomes open.
        previous = json.loads((ROOT / "bootstrap/flux/release-selector/platform-release-identity.v3.schema.json").read_text())
        comparable = copy.deepcopy(schema)
        comparable["$id"] = previous["$id"]
        comparable["properties"]["schema"] = previous["properties"]["schema"]
        del comparable["properties"]["execution"]
        comparable["required"].remove("execution")
        for name in ("event", "workflow"):
            comparable["properties"]["platform_release"]["properties"][name] = previous["properties"]["platform_release"]["properties"][name]
        comparable["properties"]["release"]["properties"]["target_commitish"] = previous["properties"]["release"]["properties"]["target_commitish"]
        self.assertEqual(comparable, previous)


if __name__ == "__main__":
    unittest.main()
