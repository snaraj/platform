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
BACKLOG = load_script("ci/release_backlog.py", module_name="release_v4_backlog")
EPOCH_SCRIPT = ROOT / "scripts/ci/platform_release_epoch.py"
EXECUTOR = "e" * 40
EXECUTOR_TREE = "f" * 40
FIXTURE_DIRECTORY = Path(__file__).resolve().parent / "fixtures_release_identity"
# Every published v4 edge's immutable identity asset, with the digest its REST
# record reports. The digests are the control: they are what makes an edited
# fixture fail before it can prove anything, and PROVENANCE.md transcribes them.
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
    "v0.1.90": "5c871591b776efb56c80f803b0122ef6a438c71430359425ff47ed715f2cdf48",
    "v0.1.91": "dbf4aae45fcb489f09d7302654a13fd93f97b16f671a3844153917fb922c6f4b",
    "v0.1.92": "0379fc667e68621cf11515c405ebaac2db7c501a0ae80356d3f7d07208f89d5a",
    "v0.1.93": "faacd90559806609f25efbfc6771127bd22034809663df888e4a90c03e2caaf0",
    "v0.1.94": "20528ec98a5f3d2fc3bce6f3db0002d416cdb7e3fab2cda0fb011c3e1c6bb8af",
}
# The window is not a list any more: it is the repository's own tag ledger.
# These tests read it from the committed derivation dump rather than re-walking
# all 86 post-floor tags per test module; `LedgerDerivationTests` in
# test_platform_release_recovery.py proves the shipped code reproduces this
# dump from git, and the dump itself was taken from the repository.
DERIVED_WINDOW = json.loads(
    (FIXTURE_DIRECTORY / "derived-window-2026-09-23.json").read_bytes())


def ledger_from_dump():
    edges, base_tag, base_sha = [], E.TERMINAL_V3_TAG, E.TERMINAL_V3_SOURCE
    for row in DERIVED_WINDOW["edges"]:
        derived = row["derived"]
        edges.append(BACKLOG.Edge(
            row["tag"], derived["source_sha"], base_tag, base_sha,
            derived["fragment_path"], "2026-09-11T00:00:00+00:00", derived["tree_sha"],
            derived["parent_sha"], derived["fragment_sha256"],
            tuple((path, derived["workflows"][path]) for path in BACKLOG.WORKFLOW_AUDIT_PATHS)))
        base_tag, base_sha = row["tag"], derived["source_sha"]
    return tuple(edges)


LEDGER = ledger_from_dump()
LEDGER_TAGS = tuple(edge.tag for edge in LEDGER)
RECOVERY_TAG = "v0.1.81"
RECOVERY_EDGE = next(edge for edge in LEDGER if edge.tag == RECOVERY_TAG)
RECOVERY_FIXTURE = FIXTURE_DIRECTORY / f"{RECOVERY_TAG}-platform-release-identity.v4.json"
_PUBLISHED = json.loads(RECOVERY_FIXTURE.read_bytes())
# A real executor of a real published edge: a LATER first-parent commit of main
# than the source it published. Nothing about it is pinned anywhere.
RECOVERY_EXECUTOR = _PUBLISHED["execution"]["source_sha"]
RECOVERY_RELEASE_ID = _PUBLISHED["release"]["id"]
LAST_LEDGER_TAG = LEDGER_TAGS[-1]
FIRST_UNPUBLISHED_TAG = E.next_tag(LAST_LEDGER_TAG)


def relation(value):
    """The executor relation this checkout proves for one identity payload."""
    return C._identity_executor_descends(ROOT, value)


def main_ci(source, run_id):
    return {"event": "push", "head_sha": source, "ref": "refs/heads/main",
            "run_id": run_id, "run_attempt": 1, "conclusion": "success",
            "workflow": ".github/workflows/pull-request.yml"}


def evidence(recovering=True):
    """One v4 identity payload, built from facts the repository itself holds."""
    edge = RECOVERY_EDGE
    source = edge.source_sha if recovering else EXECUTOR
    tree = edge.tree_sha if recovering else EXECUTOR_TREE
    tag = RECOVERY_TAG if recovering else FIRST_UNPUBLISHED_TAG
    executor = RECOVERY_EXECUTOR if recovering else EXECUTOR
    release_id = RECOVERY_RELEASE_ID if recovering else 300
    original_ci = main_ci(source, 401 if recovering else 400)
    return {
        "schema": "https://snaraj.dev/schemas/platform-release-identity/v4",
        "repository": "snaraj/platform", "repository_id": 1327645656,
        "source": {"merge_sha": source, "tree_sha": tree, "protected_ref": "refs/heads/main"},
        "tag": {"name": tag, "object_sha": "b" * 40, "object_type": "tag", "peeled_commit": source},
        "predecessor": {"tag": edge.base_tag if recovering else LAST_LEDGER_TAG,
                        "peeled_commit": edge.base_sha if recovering else LEDGER[-1].source_sha},
        "changelog": {"fragment_path": edge.fragment_path if recovering else "changelog.d/1-example.md",
                      "fragment_sha256": "sha256:" + (edge.fragment_sha256 if recovering else "a" * 64)},
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


def validate(value, *, run_records=True, expected=None):
    """Validate one payload against the facts a caller derives independently.

    `expected` is what git and the ledger say the edge is; the payload is what
    the Release claims. They are the same object in the accepting case and
    differ in every mutation, which is how a substituted claim is caught.
    """
    expected = value if expected is None else expected
    identity, bundle, release, runs = records(value)
    descends = relation(value)
    C.validate_identity_release_record(
        release, identity=identity, bundle=bundle, tag=expected["tag"]["name"],
        source_sha=expected["source"]["merge_sha"], tree_sha=expected["source"]["tree_sha"],
        tag_object_sha=expected["tag"]["object_sha"], api_repository="snaraj/platform",
        api_repository_id=1327645656, executor_descends=descends,
    )
    if run_records:
        C.validate_identity_run_records(identity, runs[0], runs[1],
                                        execution_main_run_record=runs[2],
                                        executor_descends=descends)


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
                      api_repository="snaraj/platform", api_repository_id=1327645656, staged=True,
                      executor_descends=relation(value))
        return release, kwargs

    def test_staged_recovery_accepts_bound_temporary_and_canonical_tags(self):
        for token in ("untagged-" + "a" * 20, "untagged-" + "b" * 20):
            release, kwargs = self.staged_recovery(token)
            for tag in (token, RECOVERY_TAG):
                with self.subTest(token=token, tag=tag):
                    try:
                        C.validate_identity_release_record({**release, "tag_name": tag}, **kwargs)
                    except C.ContractError as error:
                        self.fail(f"bound staged draft refused: {error}")

    def test_staged_recovery_refuses_foreign_record_and_asset_namespaces(self):
        release, kwargs = self.staged_recovery()
        for tag in (None, E.next_tag(RECOVERY_TAG), "untagged-" + "b" * 20, "untagged-" + "A" * 20,
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
                           ("target_commitish", "a" * 40), ("name", "Platform " + E.next_tag(RECOVERY_TAG)),
                           ("id", 301), ("author", {"login": "other", "id": 1})):
            with self.subTest(field=key), self.assertRaises(C.ContractError):
                C.validate_identity_release_record({**release, key: value}, **kwargs)
        for key, value in (("source_sha", "a" * 40), ("tag", E.next_tag(RECOVERY_TAG)),
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
        record = {"id": 300, "tag_name": RECOVERY_TAG, "name": "Platform " + RECOVERY_TAG,
                  "target_commitish": "main",
                  "body": "exact marker", "draft": True, "prerelease": False, "immutable": False,
                  "author": {"login": "github-actions[bot]", "id": 41898282}, "assets": []}
        def check(candidate):
            C.validate_draft_release_record(candidate, tag=RECOVERY_TAG,
                                             source_sha=value["source"]["merge_sha"],
                                             title="Platform " + RECOVERY_TAG, body="exact marker",
                                             expected_release_id=300, recovering=True)
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
                    "--executor-repository", str(ROOT),
                    "--main-run-json", paths[0], "--platform-run-json", paths[1],
                    "--execution-main-run-json", paths[2]]
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(C.main(), 0)
            runs[2]["id"] = 999
            Path(paths[2]).write_text(json.dumps(runs[2]))
            with mock.patch.object(sys, "argv", args), mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(C.main(), 1)

    def test_the_epoch_cli_states_both_commits_of_a_recovery_relation(self):
        """A recovery policy names a DIFFERENT signing subject, so the caller
        must state the relation and it must actually be one."""
        recovery = ["epoch", RECOVERY_TAG, "--recovering", "--source-sha",
                    RECOVERY_EDGE.source_sha, "--executor-sha", RECOVERY_EXECUTOR]
        with mock.patch.object(sys, "argv", recovery), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(E.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["publisher_workflow"], E.RECOVERY_WORKFLOW)
        with mock.patch.object(sys, "argv", ["epoch", RECOVERY_TAG]), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(E.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["publisher_workflow"],
                         ".github/workflows/platform-release.yml")
        for argv in (["epoch", RECOVERY_TAG, "--recovering"],
                     ["epoch", RECOVERY_TAG, "--recovering", "--source-sha", RECOVERY_EDGE.source_sha],
                     ["epoch", RECOVERY_TAG, "--recovering", "--executor-sha", RECOVERY_EXECUTOR],
                     ["epoch", RECOVERY_TAG, "--recovering", "--source-sha", RECOVERY_EDGE.source_sha,
                      "--executor-sha", RECOVERY_EDGE.source_sha],
                     ["epoch", "v0.1.80", "--recovering", "--source-sha", "a" * 40,
                      "--executor-sha", "b" * 40],
                     ["epoch", RECOVERY_TAG, "--source-sha", "a" * 40, "--executor-sha", "b" * 40],
                     ["epoch", RECOVERY_TAG, "--recovering", "--git-remote",
                      "https://github.com/snaraj/platform.git"]):
            with self.subTest(argv=argv), mock.patch.object(sys, "argv", argv), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(E.main(), 1)
                self.assertTrue(output.getvalue().startswith("RELEASE_EPOCH_DENIED"))
        for tag, edge in ((edge.tag, edge) for edge in LEDGER):
            self.assertEqual(E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag, edge.base_tag,
                             edge.base_sha, edge.source_sha, recovering=True)["version"], 4)
            for source, base in ((None, edge.base_sha), (edge.source_sha, edge.source_sha),
                                 (E.TERMINAL_V3_SOURCE, edge.base_sha)):
                with self.subTest(tag=tag, source=source), self.assertRaises(ValueError):
                    E.publication(E.NEW_REPOSITORY, E.REPOSITORY_ID, tag, edge.base_tag, base, source)
        self.assertEqual(E.release_target(RECOVERY_EDGE.source_sha, recovering=True), "main")
        self.assertEqual(E.release_target(RECOVERY_EDGE.source_sha, recovering=False),
                         RECOVERY_EDGE.source_sha)
        with self.assertRaises(ValueError):
            E.release_target("a" * 39, recovering=False)

    def test_every_published_identity_validates_through_the_executor_relation(self):
        """The class guard: each published edge's real bytes, at this head.

        The membership refusal and its per-edge pins are gone (issue #395), so
        what has to hold for the whole class is the RELATION: every executor
        that ever published one of these edges is a later first-parent commit
        of main than the edge it published, and main still contains it. A drain
        that publishes eight edges from one executor needs no new row for any
        of them, and this walks every immutable asset committed beside it to
        prove that offline, before anyone dispatches.
        """
        self.assertEqual(
            sorted(path.name for path in FIXTURE_DIRECTORY.glob("v*.json")),
            sorted(f"{tag}-platform-release-identity.v4.json" for tag in PUBLISHED_IDENTITIES))
        self.assertEqual(LEDGER_TAGS, tuple(PUBLISHED_IDENTITIES)[:len(LEDGER_TAGS)])
        recovering = 0
        for tag, digest in PUBLISHED_IDENTITIES.items():
            with self.subTest(tag=tag):
                raw = (FIXTURE_DIRECTORY / f"{tag}-platform-release-identity.v4.json").read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                published = json.loads(raw)
                self.assertEqual(published["tag"]["name"], tag)
                descends = relation(published)
                # The production path, unmocked: repository, epoch, predecessor
                # and then the executor relation proved against this checkout.
                E.validate_identity(published, executor_descends=descends)
                E.validate_execution(published, executor_descends=descends)
                if E.recovering_identity(published):
                    recovering += 1
                    self.assertIs(descends, True)
                    # Without the ancestry proof the same bytes refuse: the
                    # relation is the control, not a shape check.
                    with self.assertRaisesRegex(ValueError, "needs an ancestry proof"):
                        E.validate_execution(published)
                    with self.assertRaisesRegex(ValueError, "later first-parent commit"):
                        E.validate_execution(published, executor_descends=False)
                else:
                    self.assertIsNone(descends)
        self.assertGreater(recovering, 1)

    def test_the_v0_1_82_outage_executor_is_admitted_and_a_stranger_is_not(self):
        """Issue #393's outage input, replayed both ways.

        `76f60b30` published `v0.1.82` and seven edges after it, and was then
        itself frozen as `v0.1.93`'s source; the membership refusal it met is
        what needed a pin per published edge. The relation admits it with no
        row at all, and still refuses every executor that does not descend.
        """
        published = json.loads(
            (FIXTURE_DIRECTORY / "v0.1.82-platform-release-identity.v4.json").read_bytes())
        executor = published["execution"]["source_sha"]
        source = published["source"]["merge_sha"]
        head = C._git(ROOT, "rev-parse", "HEAD")
        self.assertTrue(C.executor_descends(
            ROOT, source_sha=source, executor_sha=executor, protected_sha=head))
        E.validate_execution(published, executor_descends=True)
        # The executor is also a later frozen SOURCE, which is precisely the
        # shape the retired membership test refused.
        self.assertIn(executor, {edge.source_sha for edge in LEDGER})
        for name, other in (("its own source", source),
                            ("its parent", RECOVERY_EDGE.base_sha),
                            ("the terminal v3 source", E.TERMINAL_V3_SOURCE),
                            ("an earlier edge", LEDGER[0].source_sha)):
            with self.subTest(executor=name):
                self.assertFalse(C.executor_descends(
                    ROOT, source_sha=source, executor_sha=other, protected_sha=head))
        # A commit main only reached through a merge is an ancestor without
        # ever having been main, so reachability alone is not the relation.
        merged = C._git(ROOT, "rev-list", "--max-count=1", "--merges", "HEAD")
        if merged:
            side = C._git(ROOT, "rev-parse", merged + "^2")
            self.assertTrue(C._is_ancestor(ROOT, side, head))
            self.assertFalse(C.executor_descends(
                ROOT, source_sha=source, executor_sha=side, protected_sha=head))
        # An executor main no longer contains is refused by the second half.
        self.assertFalse(C.executor_descends(
            ROOT, source_sha=source, executor_sha=executor, protected_sha=source))

    def test_execution_semantics_refuse_unknown_fields_and_foreign_executors(self):
        exact = evidence()
        changes = [({"extra": True}, "execution"), ({"extra": True}, "main_ci")]
        for extra, field in changes:
            value = copy.deepcopy(exact)
            target = value["execution"] if field == "execution" else value["execution"]["main_ci"]
            target.update(extra)
            with self.subTest(field=field), self.assertRaises(ValueError):
                E.validate_execution(value, executor_descends=True)
        for replacement in (None, [], "execution"):
            value = copy.deepcopy(exact)
            value["execution"] = replacement
            with self.subTest(shape=replacement), self.assertRaises(ValueError):
                E.validate_execution(value, executor_descends=True)
        for key, replacement in (("source_sha", None), ("tree_sha", 42), ("main_ci", None),
                                 ("main_ci", [])):
            value = copy.deepcopy(exact)
            value["execution"][key] = replacement
            with self.subTest(field=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value, executor_descends=True)
        for key, replacement in (("conclusion", "failure"), ("event", "workflow_dispatch"),
                ("head_sha", "a" * 40), ("ref", "refs/heads/other"), ("workflow", "foreign.yml"),
                ("run_id", True), ("run_id", 0), ("run_attempt", True), ("run_attempt", 0)):
            value = copy.deepcopy(exact)
            value["execution"]["main_ci"][key] = replacement
            with self.subTest(ci=key, replacement=replacement), self.assertRaises(ValueError):
                E.validate_execution(value, executor_descends=True)
        # Recovery-shaped evidence with no proof refuses rather than defaulting.
        with self.assertRaisesRegex(ValueError, "needs an ancestry proof"):
            E.validate_execution(copy.deepcopy(exact))
        with self.assertRaisesRegex(ValueError, "later first-parent commit"):
            E.validate_execution(copy.deepcopy(exact), executor_descends=False)
        E.validate_execution(copy.deepcopy(exact), executor_descends=True)
        # Recovery-shaped publisher fields on an equal-SHA publication, and
        # ordinary publisher fields on a recovery one, both refuse: the
        # recorded workflow, event and head must agree with the relation.
        crossed = copy.deepcopy(exact)
        crossed["execution"]["source_sha"] = crossed["source"]["merge_sha"]
        crossed["execution"]["tree_sha"] = crossed["source"]["tree_sha"]
        crossed["execution"]["main_ci"] = copy.deepcopy(crossed["main_ci"])
        with self.assertRaisesRegex(ValueError, "disagrees with the derived relation"):
            E.validate_execution(crossed, executor_descends=True)
        for key, replacement in (("workflow", ".github/workflows/platform-release.yml"),
                                 ("event", "workflow_run"),
                                 ("head_sha", exact["source"]["merge_sha"])):
            value = copy.deepcopy(exact)
            value["platform_release"][key] = replacement
            with self.subTest(publisher=key), \
                    self.assertRaisesRegex(ValueError, "disagrees with the derived relation"):
                E.validate_execution(value, executor_descends=True)
        ordinary = evidence(False)
        for key, replacement in (("workflow", E.RECOVERY_WORKFLOW),
                                 ("event", "workflow_dispatch")):
            value = copy.deepcopy(ordinary)
            value["platform_release"][key] = replacement
            with self.subTest(ordinary_publisher=key), \
                    self.assertRaisesRegex(ValueError, "disagrees with the derived relation"):
                E.validate_execution(value)
        for key, replacement in (("tree_sha", "a" * 40), ("main_ci", main_ci(EXECUTOR, 401))):
            value = evidence(False)
            value["execution"][key] = replacement
            with self.subTest(ordinary=key), \
                    self.assertRaisesRegex(ValueError, "ordinary publication"):
                E.validate_execution(value)

    def test_policy_preserves_old_epochs_and_closes_recovery_subjects(self):
        for tag, version in (("v0.1.69", 1), ("v0.1.77", 2), ("v0.1.80", 3), ("v0.1.81", 4),
                             (FIRST_UNPUBLISHED_TAG, 4)):
            self.assertEqual(E.identity(tag)["version"], version)
        # The recovery subject is no longer a property of the tag NUMBER: any
        # v4 tag carries it when, and only when, the relation says so.
        for tag in LEDGER_TAGS:
            selected = E.identity(tag, recovering=True)
            self.assertEqual(selected["publisher_workflow"], ".github/workflows/platform-release-recovery.yml")
            self.assertEqual(selected["publisher_event"], "workflow_dispatch")
            self.assertEqual(selected["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release-recovery.yml@refs/heads/main")
            self.assertEqual(E.identity(tag)["publisher_event"], "workflow_run")
        self.assertEqual(E.identity(FIRST_UNPUBLISHED_TAG)["publisher_event"], "workflow_run")
        self.assertEqual(E.identity(FIRST_UNPUBLISHED_TAG)["subject"], "https://github.com/snaraj/platform/.github/workflows/platform-release.yml@refs/heads/main")
        for tag in ("v0.1.69", "v0.1.77", "v0.1.80"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                E.identity(tag, recovering=True)

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
            # A rerun attempt is refused by the workflow context rather than by
            # the payload: `context()` admits only GITHUB_RUN_ATTEMPT 1 and
            # `prove_context` binds the record to this exact run.
            (("source", "tree_sha"), "a" * 40),
        ]
        # The ORIGINAL run, the fragment and the predecessor are no longer
        # transcribed anywhere: they are derived from the tag ledger and the
        # API by the reader, and
        # `RecoveryReleaseTests.test_a_published_identity_must_match_the_derived_ledger`
        # in test_platform_release_recovery.py refuses each of them there.
        for path, replacement in mutations:
            changed = copy.deepcopy(exact)
            parent = changed
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises((C.ContractError, ValueError)):
                validate(changed, run_records=False, expected=exact)
        for field in ("source_sha", "tree_sha", "main_ci"):
            changed = copy.deepcopy(exact)
            del changed["execution"][field]
            with self.subTest(missing=field), self.assertRaises(C.ContractError):
                validate(changed, expected=exact)

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
                    C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2], executor_descends=True)
        with self.assertRaisesRegex(C.ContractError, "requires executor main CI proof"):
            C.validate_identity_run_records(identity, runs[0], runs[1], executor_descends=True)
        for repository_id in (True, 1):
            changed = evidence()
            changed["repository_id"] = repository_id
            raw, _, _, actual = records(changed)
            with self.assertRaisesRegex(C.ContractError, "run identity epoch"):
                C.validate_identity_run_records(raw, *actual[:2], execution_main_run_record=actual[2], executor_descends=True)
        changed = copy.deepcopy(runs)
        changed[2]["head_commit"]["tree_id"] = "a" * 40
        with self.assertRaises(C.ContractError):
            C.validate_identity_run_records(identity, changed[0], changed[1], execution_main_run_record=changed[2], executor_descends=True)

    def test_pending_reader_mode_never_substitutes_original_identity_or_success(self):
        identity, _, _, runs = records(evidence())
        for status in ("queued", "in_progress", "pending", "requested", "waiting"):
            pending = copy.deepcopy(runs)
            pending[1].update(status=status, conclusion=None)
            C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2], platform_pending=True, executor_descends=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2], executor_descends=True)
            for row, field, replacement in ((0, "status", "queued"), (2, "status", "queued"),
                    (1, "conclusion", "success"), (1, "conclusion", "failure"), (1, "status", "unknown"),
                    (1, "status", "completed"), (1, "id", 501), (1, "run_attempt", 2), (1, "head_sha", "a" * 40)):
                changed = copy.deepcopy(pending)
                changed[row][field] = replacement
                with self.subTest(status=status, row=row, field=field), self.assertRaises(C.ContractError):
                    C.validate_identity_run_records(identity, *changed[:2], execution_main_run_record=changed[2], platform_pending=True, executor_descends=True)
            with self.assertRaises(C.ContractError):
                C.validate_identity_run_records(identity, *pending[:2], execution_main_run_record=pending[2],
                                                platform_pending=True, platform_conclusion="failure",
                                                executor_descends=True)
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
        # A recovery payload with no ancestry proof refuses here as well: the
        # run-record validator reaches the same executor relation.
        raw, _, _, actual_runs = records(evidence())
        with self.assertRaisesRegex(C.ContractError, "signed publication execution"):
            C.validate_identity_run_records(raw, *actual_runs[:2],
                                            execution_main_run_record=actual_runs[2])

    def test_default_target_hint_is_exact_and_does_not_replace_the_tag_source(self):
        for target in ("master", EXECUTOR, evidence()["source"]["merge_sha"], "refs/heads/main"):
            changed = evidence()
            changed["release"]["target_commitish"] = target
            with self.subTest(target=target), self.assertRaises(C.ContractError):
                validate(changed)

    def test_renderer_separates_actual_execution_and_preserves_source(self):
        expected = evidence()
        source = expected["source"]["merge_sha"]
        window = C.TransitionWindow(
            expected["predecessor"]["peeled_commit"], expected["predecessor"]["tag"],
            C.Intent(source, C.Version.parse(RECOVERY_TAG.removeprefix("v"))),
            expected["changelog"]["fragment_path"], expected["changelog"]["fragment_sha256"][7:])

        def git(_repository, *args):
            return expected["source"]["tree_sha"] if args[-1] == source + "^{tree}" else EXECUTOR_TREE

        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), \
                mock.patch.object(C, "_git", side_effect=git), \
                mock.patch.object(C, "discover_transition_window", return_value=window), \
                mock.patch.object(C, "_identity_executor_descends", return_value=True):
            kwargs = dict(expected_base_sha=window.base_sha, expected_base_tag=window.base_tag,
                tag_object_sha="b" * 40, release_id=RECOVERY_RELEASE_ID,
                main_run_id=expected["main_ci"]["run_id"],
                main_run_attempt=1, platform_run_id=500, platform_run_attempt=1,
                github_repository="snaraj/platform", github_repository_id=1327645656,
                execution_sha=RECOVERY_EXECUTOR, execution_main_run_id=400,
                execution_main_run_attempt=1,
            )
            rendered = C.render_release_identity(ROOT, source, RECOVERY_TAG, **kwargs)
            for change in ({"github_repository": None, "github_repository_id": None},
                           {"execution_main_run_id": None}, {"execution_main_run_id": True},
                           {"execution_main_run_id": 0}, {"execution_main_run_attempt": None},
                           {"execution_main_run_attempt": True}, {"execution_main_run_attempt": 0}):
                message = "repository" if "github_repository" in change else "executor main CI requires"
                with self.subTest(change=change), self.assertRaisesRegex(C.ContractError, message):
                    C.render_release_identity(ROOT, source, RECOVERY_TAG, **{**kwargs, **change})
            # An executor the checkout cannot place after the source is refused
            # at render time as well as at validation time.
            with mock.patch.object(C, "_identity_executor_descends", return_value=False), \
                    self.assertRaisesRegex(C.ContractError, "release identity epoch"):
                C.render_release_identity(ROOT, source, RECOVERY_TAG, **kwargs)
        self.assertEqual(json.loads(rendered), expected)
        ordinary = evidence(False)
        window = C.TransitionWindow(
            ordinary["predecessor"]["peeled_commit"], LAST_LEDGER_TAG,
            C.Intent(EXECUTOR, C.Version.parse(FIRST_UNPUBLISHED_TAG.removeprefix("v"))),
            "changelog.d/1-example.md", "a" * 64)
        with mock.patch.object(C, "_exact_commit", side_effect=lambda _repo, sha, _field: sha), \
                mock.patch.object(C, "_git", return_value=EXECUTOR_TREE), \
                mock.patch.object(C, "discover_transition_window", return_value=window):
            rendered = C.render_release_identity(ROOT, EXECUTOR, FIRST_UNPUBLISHED_TAG,
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
