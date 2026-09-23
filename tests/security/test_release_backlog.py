"""Release-backlog derivation, the owner's tag command, and the watchdog.

Issue #317: the publisher for one source died mid-flight, ten later merges
queued behind it unnoticed for two weeks, and the manual repair produced ten
annotated tags by hand — one of which the contract then refused over a byte no
operator could see. The three subjects here replace that hand work without
moving any authority: the derivation is the publisher's own, the owner still
creates every tag with the owner's own credentials, and the watchdog only
reads.

Every guard these subjects add is exercised in both directions: the accepted
input and the exact regression it exists to refuse.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from .support import hermetic_git_environment, load_script, REPO_ROOT

BACKLOG = load_script("ci/release_backlog.py", module_name="release_backlog_subject")
PREPARE = load_script(
    "prepare_recovery_tags.py", module_name="prepare_recovery_tags_subject"
)
# Each ``load_script`` call executes its own copy of the subject, and each copy
# loads its own copy of the contract, so the owner command would otherwise carry
# a second ``ContractError`` class and a second ledger-floor constant that no
# fixture patch reaches. Binding both subjects to one contract instance keeps
# every assertion and every patch in this file pointed at the same objects.
PREPARE.B = BACKLOG
PREPARE.C = BACKLOG.C
CONTRACT = BACKLOG.C
# Emptied rather than deleted: mock.patch.dict restores exactly what it
# replaced, and an empty value is falsy to the command's own check.
WITHOUT_CI = {marker: "" for marker in PREPARE.CI_MARKERS}
NOW = dt.datetime(2026, 9, 22, 12, 0, tzinfo=dt.timezone.utc)


class Ledger:
    """A disposable platform repository with a real, walkable tag ledger."""

    def __init__(self, root: Path):
        self.root = root
        self.git("init", "-q")
        for key, value in (
            ("maintenance.auto", "false"),
            ("gc.auto", "0"),
            ("core.autocrlf", "false"),
            ("user.name", "Fixture Owner"),
            ("user.email", "fixture@example.invalid"),
        ):
            self.git("config", "--local", key, value)
        self.git("branch", "-m", "main")
        (root / "VERSION").write_text("0.1.9\n", encoding="utf-8", newline="\n")
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [0.1.9] - 2026-08-20\n\n- Legacy floor.\n",
            encoding="utf-8",
            newline="\n",
        )
        self.floor = self.commit("legacy migration floor")
        self.tag(CONTRACT.TAG_LEDGER_FLOOR_TAG, self.floor)

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=hermetic_git_environment(
                identity=("Fixture Owner", "fixture@example.invalid")
            ),
        ).stdout.strip()

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def fragment(self, issue: int, slug: str, *, extra: str | None = None) -> str:
        directory = self.root / "changelog.d"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{issue}-{slug}.md").write_text(
            f"### Security\n\n- {slug} edge.\n", encoding="utf-8", newline="\n"
        )
        if extra is not None:
            (directory / extra).write_text(
                "### Added\n\n- second fragment.\n", encoding="utf-8", newline="\n"
            )
        return self.commit(f"add {issue}-{slug}")

    def tag(
        self,
        name: str,
        target: str,
        *,
        message: str | None = None,
        tagger_name: str = CONTRACT.RELEASE_TAGGER_NAME,
        tagger_email: str = CONTRACT.RELEASE_TAGGER_EMAIL,
        date: str | None = None,
    ) -> None:
        resolved = date or self.git("show", "-s", "--format=%cI", target)
        environment = hermetic_git_environment(
            identity=("Fixture Owner", "fixture@example.invalid")
        )
        environment.update(
            GIT_COMMITTER_NAME=tagger_name,
            GIT_COMMITTER_EMAIL=tagger_email,
            GIT_COMMITTER_DATE=resolved,
        )
        text = message if message is not None else (
            f"Platform release {name} from {target}"
        )
        subprocess.run(
            ["git", "-C", str(self.root), "tag", "-a", "-m", text, name, target],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=environment,
        )

    def raw_tag(self, name: str, target: str, message: str) -> None:
        """Write a tag object byte-for-byte, past git's own message cleanup.

        ``git tag -a -m`` normalises what it is handed, so the encodings this
        acceptance must still refuse — a second terminator, a leading newline,
        CRLF — can only be built at the object layer.
        """
        date = self.git("show", "-s", "--format=%cI", target)
        moment = dt.datetime.fromisoformat(date)
        payload = (
            f"object {target}\ntype commit\ntag {name}\n"
            f"tagger {CONTRACT.RELEASE_TAGGER_NAME} "
            f"<{CONTRACT.RELEASE_TAGGER_EMAIL}> "
            f"{int(moment.timestamp())} {moment.strftime('%z')}\n\n{message}"
        ).encode("utf-8")
        created = subprocess.run(
            ["git", "-C", str(self.root), "hash-object", "-t", "tag", "-w", "--stdin"],
            check=True, input=payload, stdout=subprocess.PIPE, timeout=60,
            env=hermetic_git_environment(),
        )
        self.git("update-ref", f"refs/tags/{name}",
                 created.stdout.decode("ascii").strip())

    def floor_patch(self):
        return mock.patch.object(CONTRACT, "TAG_LEDGER_FLOOR_SHA", self.floor)


class PlanDerivationTests(unittest.TestCase):
    """The plan is the publisher's ledger rule, not a second opinion of it."""

    def test_every_untagged_first_parent_commit_becomes_exactly_one_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            first = ledger.fragment(301, "first")
            ledger.tag("v0.1.10", first)
            second = ledger.fragment(302, "second")
            third = ledger.fragment(303, "third")
            with ledger.floor_patch():
                edges = BACKLOG.plan(ledger.root, "HEAD")
            self.assertEqual([edge.tag for edge in edges], ["v0.1.11", "v0.1.12"])
            self.assertEqual([edge.source_sha for edge in edges], [second, third])
            self.assertEqual([edge.base_tag for edge in edges], ["v0.1.10", "v0.1.11"])
            self.assertEqual([edge.base_sha for edge in edges], [first, second])
            self.assertEqual(
                [edge.fragment_path for edge in edges],
                ["changelog.d/302-second.md", "changelog.d/303-third.md"],
            )
            self.assertEqual(
                edges[0].message, f"Platform release v0.1.11 from {second}"
            )
            self.assertEqual(
                edges[0].source_date,
                ledger.git("show", "-s", "--format=%cI", second),
            )
            self.assertEqual(
                json.loads(json.dumps(edges[0].as_dict()))["tag"], "v0.1.11"
            )

    def test_a_fully_tagged_head_plans_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            head = ledger.fragment(301, "first")
            ledger.tag("v0.1.10", head)
            with ledger.floor_patch():
                self.assertEqual(BACKLOG.plan(ledger.root, "HEAD"), ())

    def test_the_plan_refuses_every_shape_the_publisher_refuses(self):
        for case in ("two-fragments", "no-fragment", "merge-commit", "bound"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                ledger = Ledger(Path(temporary))
                first = ledger.fragment(301, "first")
                ledger.tag("v0.1.10", first)
                if case == "two-fragments":
                    ledger.fragment(302, "second", extra="399-extra.md")
                elif case == "no-fragment":
                    (ledger.root / "unrelated.txt").write_text(
                        "no release consequence\n", encoding="utf-8", newline="\n"
                    )
                    ledger.commit("unrelated change only")
                elif case == "merge-commit":
                    ledger.git("checkout", "-q", "-b", "side", first)
                    ledger.fragment(302, "side")
                    ledger.git("checkout", "-q", "main")
                    ledger.fragment(303, "main-side")
                    ledger.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
                else:
                    ledger.fragment(302, "second")
                    ledger.fragment(303, "third")
                with ledger.floor_patch(), self.assertRaises(CONTRACT.ContractError):
                    if case == "bound":
                        with mock.patch.object(BACKLOG, "MAX_PLAN_EDGES", 1):
                            BACKLOG.plan(ledger.root, "HEAD")
                    else:
                        BACKLOG.plan(ledger.root, "HEAD")

    def test_a_head_outside_the_ledger_line_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            first = ledger.fragment(301, "first")
            ledger.tag("v0.1.10", first)
            ledger.git("checkout", "-q", "-b", "detached", ledger.floor)
            ledger.fragment(302, "elsewhere")
            with ledger.floor_patch(), self.assertRaises(CONTRACT.ContractError):
                BACKLOG.plan(ledger.root, "HEAD")

    def test_revision_resolution_refuses_malformed_and_unknown_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            self.assertEqual(BACKLOG.resolve(ledger.root, "HEAD"), ledger.floor)
            for revision in ("", "--upload-pack=touch", None, "refs/heads/absent"):
                with self.subTest(revision=revision), self.assertRaises(
                    CONTRACT.ContractError
                ):
                    BACKLOG.resolve(ledger.root, revision)


class PreparedTagTests(unittest.TestCase):
    """The owner's one command creates only exact tags, and only locally first."""

    def remote(self, ledger: Ledger, temporary: Path) -> Path:
        """A bare origin whose `main` the command's ancestry guard reads.

        The tracking ref is part of the fixture, not decoration: the command
        refuses any head `refs/remotes/origin/main` does not already contain,
        so a fixture without one would only ever exercise that refusal.
        """
        bare = temporary / "remote.git"
        subprocess.run(
            ["git", "init", "-q", "--bare", str(bare)],
            check=True, capture_output=True, timeout=60,
            env=hermetic_git_environment(),
        )
        ledger.git("remote", "add", "origin", str(bare))
        ledger.git("push", "-q", "origin", "refs/heads/main:refs/heads/main")
        ledger.git("fetch", "-q", "origin")
        return bare

    def remote_tags(self, bare: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(bare), "tag", "--list"],
            check=True, capture_output=True, text=True, timeout=60,
            env=hermetic_git_environment(),
        ).stdout.strip()

    def run_prepare(self, ledger: Ledger, *, push: bool):
        # This battery runs inside CI, where the runner markers the command
        # refuses on are genuinely set. Clearing them is what lets the positive
        # paths execute at all; the refusal itself is proved separately, with
        # exactly one marker restored.
        stream = io.StringIO()
        with ledger.floor_patch(), mock.patch.dict(PREPARE.os.environ, WITHOUT_CI):
            code = PREPARE.prepare(
                ledger.root, "HEAD", push=push, remote="origin", stream=stream
            )
        return code, stream.getvalue()

    def two_pending(self, root: Path):
        ledger = Ledger(root)
        first = ledger.fragment(301, "first")
        ledger.tag("v0.1.10", first)
        second = ledger.fragment(302, "second")
        third = ledger.fragment(303, "third")
        return ledger, second, third

    def test_push_creates_exactly_the_missing_tags_in_the_exact_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, second, third = self.two_pending(root)
            bare = self.remote(ledger, Path(temporary))
            code, output = self.run_prepare(ledger, push=True)
            self.assertEqual(code, 0)
            self.assertIn("pushed v0.1.11", output)
            self.assertIn("pushed v0.1.12", output)
            for tag, target in (("v0.1.11", second), ("v0.1.12", third)):
                raw = subprocess.run(
                    ["git", "-C", str(ledger.root), "cat-file", "tag", tag],
                    check=True, capture_output=True, timeout=60,
                    env=hermetic_git_environment(),
                ).stdout.decode("utf-8")
                self.assertIn(f"object {target}\n", raw)
                self.assertIn(
                    f"tagger {CONTRACT.RELEASE_TAGGER_NAME} "
                    f"<{CONTRACT.RELEASE_TAGGER_EMAIL}>",
                    raw,
                )
                # git's own canonical encoding: exactly one terminator.
                self.assertTrue(
                    raw.endswith(f"Platform release {tag} from {target}\n")
                )
                self.assertFalse(raw.endswith("\n\n"))
                local = ledger.git("rev-parse", f"refs/tags/{tag}")
                pushed = subprocess.run(
                    ["git", "-C", str(bare), "rev-parse", f"refs/tags/{tag}"],
                    check=True, capture_output=True, text=True, timeout=60,
                    env=hermetic_git_environment(),
                ).stdout.strip()
                self.assertEqual(local, pushed)
            with ledger.floor_patch():
                self.assertEqual(BACKLOG.plan(ledger.root, "HEAD"), ())

    def test_plan_only_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, _, _ = self.two_pending(root)
            bare = self.remote(ledger, Path(temporary))
            code, output = self.run_prepare(ledger, push=False)
            self.assertEqual(code, 0)
            self.assertIn("v0.1.11", output)
            self.assertIn("Ledger edges pending a tag: 2", output)
            self.assertNotIn("pushed", output)
            self.assertEqual(ledger.git("tag", "--list", "v0.1.11", "v0.1.12"), "")
            self.assertEqual(self.remote_tags(bare), "")

    def test_an_already_exact_tag_is_a_ledger_boundary_and_is_never_rewritten(self):
        """A present exact tag leaves the plan; only the remaining edge is cut."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, second, _ = self.two_pending(root)
            self.remote(ledger, Path(temporary))
            ledger.tag("v0.1.11", second)
            before = ledger.git("rev-parse", "refs/tags/v0.1.11")
            code, output = self.run_prepare(ledger, push=True)
            self.assertEqual(code, 0)
            self.assertIn("Ledger edges pending a tag: 1", output)
            self.assertIn("pushed v0.1.12", output)
            self.assertNotIn("pushed v0.1.11", output)
            self.assertEqual(ledger.git("rev-parse", "refs/tags/v0.1.11"), before)

    def test_a_disagreeing_existing_tag_stops_before_any_write(self):
        mutations = {
            "tagger-name": {"tagger_name": "repository-owner"},
            "tagger-email": {"tagger_email": "foreign@example.invalid"},
            "tagger-date": {"date": "2020-01-02T03:04:05+00:00"},
            "message": {"message": "Platform release v0.1.11 from elsewhere"},
            "double-newline": {},
            "carriage-return": {},
        }
        # A LEADING newline is deliberately absent here: git's object format
        # ends the header with a blank line, so ``%(contents)`` cannot observe
        # one and no Git object can carry that mutation. The REST record can,
        # and the contract battery refuses it there.
        raw = {
            "double-newline": "Platform release v0.1.11 from {sha}\n\n",
            "carriage-return": "Platform release v0.1.11 from {sha}\r\n",
        }
        for case, keywords in mutations.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "work"
                root.mkdir()
                ledger, second, _ = self.two_pending(root)
                self.remote(ledger, Path(temporary))
                if case in raw:
                    ledger.raw_tag("v0.1.11", second, raw[case].format(sha=second))
                else:
                    ledger.tag("v0.1.11", second, **keywords)
                with self.assertRaises(CONTRACT.ContractError):
                    self.run_prepare(ledger, push=True)
                self.assertEqual(ledger.git("tag", "--list", "v0.1.12"), "")

    def test_a_tag_on_a_commit_the_ledger_did_not_derive_stops_the_run(self):
        for case in ("non-first-parent", "ledger-gap"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "work"
                root.mkdir()
                ledger, second, third = self.two_pending(root)
                self.remote(ledger, Path(temporary))
                if case == "non-first-parent":
                    # The next patch belongs to `second`; pointing it at a later
                    # commit skips an edge the ledger must still bind.
                    ledger.tag("v0.1.11", third)
                else:
                    ledger.tag("v0.1.13", third)
                with self.assertRaises(CONTRACT.ContractError):
                    self.run_prepare(ledger, push=True)

    def test_the_post_create_ledger_rewalk_refuses_before_any_ref_is_pushed(self):
        """The whole post-floor ledger is re-walked over the new objects.

        Per-object verification and the re-walk are different guards: the first
        judges one tag against its own derived edge, the second judges the
        refs together. With `verify` stubbed out, only the re-walk stands
        between a mis-targeted object and the remote.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, _, third = self.two_pending(root)
            bare = self.remote(ledger, Path(temporary))
            third_date = ledger.git("show", "-s", "--format=%cI", third)
            authentic = PREPARE.create

            def mis_target(repository, edge):
                # v0.1.11 belongs to `second`; cutting it at `third` skips an
                # edge the ledger must still bind. Every other field stays
                # exact, so nothing but the re-walk can notice.
                if edge.tag == "v0.1.11":
                    edge = dataclasses.replace(
                        edge, source_sha=third, source_date=third_date
                    )
                authentic(repository, edge)

            with mock.patch.object(PREPARE, "verify"), mock.patch.object(
                PREPARE, "create", mis_target
            ), self.assertRaises(CONTRACT.ContractError) as refusal:
                self.run_prepare(ledger, push=True)
            self.assertIn("must bind exactly one fragment", str(refusal.exception))
            self.assertEqual(self.remote_tags(bare), "")

    def test_a_conflicting_remote_tag_refuses_the_push_and_never_moves_it(self):
        """The refspec push is never forced, so a remote tag is never replaced.

        The remote is the immutable side: a ref that already exists there is
        exactly the object the ruleset keeps forever, and repairing it is not
        this command's authority.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, _, _ = self.two_pending(root)
            bare = self.remote(ledger, Path(temporary))
            first = ledger.git("rev-parse", "v0.1.10^{commit}")
            # A foreign v0.1.11 already published at a different target, then
            # dropped locally so the plan still derives the edge it disagrees
            # with — the shape a second operator's earlier run would leave.
            ledger.tag("v0.1.11", first,
                       message=f"Platform release v0.1.11 from {first}")
            ledger.git("push", "-q", "origin", "refs/tags/v0.1.11:refs/tags/v0.1.11")
            published = subprocess.run(
                ["git", "-C", str(bare), "rev-parse", "refs/tags/v0.1.11"],
                check=True, capture_output=True, text=True, timeout=60,
                env=hermetic_git_environment(),
            ).stdout.strip()
            ledger.git("tag", "-d", "v0.1.11")
            with self.assertRaises(subprocess.CalledProcessError):
                self.run_prepare(ledger, push=True)
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(bare), "rev-parse", "refs/tags/v0.1.11"],
                    check=True, capture_output=True, text=True, timeout=60,
                    env=hermetic_git_environment(),
                ).stdout.strip(),
                published,
            )
            # The refused push stops the run; the later edge never ships either.
            self.assertEqual(self.remote_tags(bare), "v0.1.11")

    def test_a_head_the_protected_branch_does_not_hold_is_refused(self):
        """`--head` is operator input, and the ledger it feeds is permanent."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "work"
            root.mkdir()
            ledger, second, _ = self.two_pending(root)
            bare = self.remote(ledger, Path(temporary))
            ledger.git("checkout", "-q", "-b", "side", second)
            ledger.fragment(304, "side-only")
            with self.assertRaises(CONTRACT.ContractError) as refusal:
                self.run_prepare(ledger, push=True)
            self.assertIn("refs/remotes/origin/main", str(refusal.exception))
            self.assertEqual(ledger.git("tag", "--list", "v0.1.11", "v0.1.12"), "")
            self.assertEqual(self.remote_tags(bare), "")
            # The head the runbook documents is still planned, unchanged.
            ledger.git("checkout", "-q", "main")
            code, output = self.run_prepare(ledger, push=False)
            self.assertEqual(code, 0)
            self.assertIn("Ledger edges pending a tag: 2", output)

    def test_the_command_refuses_to_run_inside_a_hosted_runner(self):
        for marker in PREPARE.CI_MARKERS:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "work"
                root.mkdir()
                ledger, _, _ = self.two_pending(root)
                stream = io.StringIO()
                with ledger.floor_patch(), mock.patch.dict(
                    PREPARE.os.environ, {**WITHOUT_CI, marker: "true"}
                ), self.assertRaises(CONTRACT.ContractError):
                    PREPARE.prepare(
                        ledger.root, "HEAD", push=True, remote="origin", stream=stream
                    )
                self.assertEqual(ledger.git("tag", "--list", "v0.1.11", "v0.1.12"), "")

    def test_redirecting_git_variables_never_reach_the_tag_command(self):
        values = PREPARE.environment(GIT_COMMITTER_NAME="pinned")
        for name in PREPARE.REDIRECTING_VARIABLES:
            self.assertNotIn(name, values)
        self.assertEqual(values["GIT_COMMITTER_NAME"], "pinned")
        with mock.patch.dict(
            PREPARE.os.environ,
            {"GIT_DIR": "/elsewhere", "GIT_CONFIG_COUNT": "1",
             "GIT_AUTHOR_NAME": "ambient", "GIT_SSH_COMMAND": "ssh -i key"},
        ):
            values = PREPARE.environment()
        for name in ("GIT_DIR", "GIT_CONFIG_COUNT", "GIT_AUTHOR_NAME"):
            self.assertNotIn(name, values)
        # Transport stays: the owner's push credential arrives through it.
        self.assertEqual(values["GIT_SSH_COMMAND"], "ssh -i key")

    def test_absent_local_tag_metadata_is_absence_not_a_silent_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            self.assertIsNone(PREPARE.tag_records(ledger.root, "v9.9.9"))
            records = PREPARE.tag_records(
                ledger.root, CONTRACT.TAG_LEDGER_FLOOR_TAG
            )
            self.assertEqual(records[0]["ref"], "refs/tags/v0.1.9")
            self.assertEqual(records[1]["object"]["sha"], ledger.floor)

    def test_the_cli_reports_a_refusal_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            with mock.patch.dict(PREPARE.os.environ, WITHOUT_CI):
                self.assertEqual(
                    PREPARE.main(
                        ["--repository", str(ledger.root), "--head", "absent"]
                    ),
                    1,
                )


class FakeReader:
    """A duck-typed Reader: recorded reads, and every write captured."""

    def __init__(self, responses: dict, repository: str = "owner/name"):
        self.responses = responses
        self.repository = repository
        self.writes: list[tuple[str, str, dict]] = []

    def get(self, path: str, *, absent: bool = False):
        if path in self.responses:
            return self.responses[path]
        if absent:
            return None
        raise CONTRACT.ContractError(f"unexpected read: {path}")

    def write(self, path: str, payload: dict, *, method: str):
        self.writes.append((method, path, payload))
        return {}


def released(tag: str) -> dict:
    return {"tag_name": tag, "draft": False}


class WatchdogTests(unittest.TestCase):
    """Read-only derivation, one issue, and no other write anywhere."""

    def boundaries(self, *tags):
        return tuple(
            CONTRACT.TagBoundary(
                CONTRACT.Version.parse(tag.removeprefix("v")), tag, index_sha
            )
            for tag, index_sha in tags
        )

    def test_unreleased_walks_back_to_the_first_published_release(self):
        boundaries = self.boundaries(
            ("v0.1.9", "a" * 40), ("v0.1.10", "b" * 40), ("v0.1.11", "c" * 40)
        )
        api = FakeReader({"/repos/owner/name/releases/tags/v0.1.9": released("v0.1.9")})
        self.assertEqual(
            [boundary.tag for boundary in BACKLOG.unreleased(boundaries, api)],
            ["v0.1.10", "v0.1.11"],
        )

    def test_a_draft_release_is_not_a_published_one(self):
        boundaries = self.boundaries(("v0.1.9", "a" * 40), ("v0.1.10", "b" * 40))
        api = FakeReader(
            {
                "/repos/owner/name/releases/tags/v0.1.10": {
                    "tag_name": "v0.1.10",
                    "draft": True,
                },
                "/repos/owner/name/releases/tags/v0.1.9": released("v0.1.9"),
            }
        )
        self.assertEqual(
            [boundary.tag for boundary in BACKLOG.unreleased(boundaries, api)],
            ["v0.1.10"],
        )

    def test_no_published_release_in_the_window_fails_closed(self):
        boundaries = self.boundaries(("v0.1.9", "a" * 40), ("v0.1.10", "b" * 40))
        with self.assertRaises(CONTRACT.ContractError):
            BACKLOG.unreleased(boundaries, FakeReader({}))

    def test_publisher_failure_is_read_from_the_newest_main_attempt(self):
        path = (
            "/repos/owner/name/actions/workflows/platform-release.yml"
            "/runs?branch=main&per_page=1"
        )
        for records, expected in (
            ([{"status": "completed", "conclusion": "success"}], False),
            ([{"status": "completed", "conclusion": "failure"}], True),
            ([{"status": "in_progress", "conclusion": None}], False),
            ([], False),
        ):
            with self.subTest(records=records):
                api = FakeReader({path: {"workflow_runs": records}})
                self.assertIs(BACKLOG.publisher_failed(api), expected)
        for malformed in ({"workflow_runs": "no"}, {}, [], {"workflow_runs": ["x"]}):
            with self.subTest(malformed=malformed), self.assertRaises(
                CONTRACT.ContractError
            ):
                BACKLOG.publisher_failed(FakeReader({path: malformed}))

    def test_the_report_alerts_only_on_a_stale_edge_or_a_failed_publisher(self):
        fresh = (NOW - dt.timedelta(hours=2)).isoformat()
        stale = (NOW - dt.timedelta(hours=30)).isoformat()
        for pending, failed, expected in (
            ((), False, False),
            ((("v0.1.10", "a" * 40, fresh),), False, False),
            ((("v0.1.10", "a" * 40, stale),), False, True),
            ((("v0.1.10", "a" * 40, fresh),), True, True),
            ((), True, True),
        ):
            with self.subTest(pending=len(pending), failed=failed):
                alerting, body = BACKLOG.report(pending, failed, NOW)
                self.assertIs(alerting, expected)
                self.assertIn(
                    f"Pending source releases: {len(pending)}", body
                )
                self.assertIn(BACKLOG.OWNER_COMMAND, body)
                if pending:
                    self.assertIn(pending[0][1], body)

    def test_a_naive_timestamp_refuses_rather_than_guessing_a_zone(self):
        with self.assertRaises(CONTRACT.ContractError):
            BACKLOG.report((("v0.1.10", "a" * 40, "2026-09-01T00:00:00"),), False, NOW)

    def test_exactly_one_issue_write_per_state_and_none_when_clear(self):
        issues = "/repos/owner/name/issues?state=open&labels=%s&per_page=100" % (
            BACKLOG.ISSUE_LABELS[0]
        )
        mine = {
            "number": 7,
            "title": BACKLOG.ISSUE_TITLE,
            "user": {"login": BACKLOG.ISSUE_AUTHOR},
        }
        api = FakeReader({issues: []})
        self.assertEqual(
            BACKLOG.announce(api, alerting=True, body="b", title=BACKLOG.ISSUE_TITLE),
            "opened",
        )
        self.assertEqual(len(api.writes), 1)
        method, path, payload = api.writes[0]
        self.assertEqual((method, path), ("POST", "/repos/owner/name/issues"))
        self.assertEqual(payload["labels"], list(BACKLOG.ISSUE_LABELS))

        api = FakeReader({issues: [mine]})
        self.assertEqual(
            BACKLOG.announce(api, alerting=True, body="b", title=BACKLOG.ISSUE_TITLE),
            "updated",
        )
        self.assertEqual(
            api.writes, [("PATCH", "/repos/owner/name/issues/7", {"body": "b"})]
        )

        api = FakeReader({issues: [mine]})
        self.assertEqual(
            BACKLOG.announce(api, alerting=False, body="b", title=BACKLOG.ISSUE_TITLE),
            "closed",
        )
        self.assertEqual(
            api.writes,
            [("PATCH", "/repos/owner/name/issues/7", {"state": "closed"})],
        )

        api = FakeReader({issues: []})
        self.assertEqual(
            BACKLOG.announce(api, alerting=False, body="b", title=BACKLOG.ISSUE_TITLE),
            "clear",
        )
        self.assertEqual(api.writes, [])

    def test_a_foreign_or_ambiguous_issue_is_never_adopted(self):
        issues = "/repos/owner/name/issues?state=open&labels=%s&per_page=100" % (
            BACKLOG.ISSUE_LABELS[0]
        )
        mine = {
            "number": 7,
            "title": BACKLOG.ISSUE_TITLE,
            "user": {"login": BACKLOG.ISSUE_AUTHOR},
        }
        for record in (
            {**mine, "user": {"login": "somebody-else"}},
            {**mine, "title": "deploy-assurance[site-drift]"},
            {**mine, "pull_request": {"url": "x"}},
        ):
            with self.subTest(record=record):
                api = FakeReader({issues: [record]})
                self.assertEqual(
                    BACKLOG.announce(
                        api, alerting=True, body="b", title=BACKLOG.ISSUE_TITLE
                    ),
                    "opened",
                )
                self.assertEqual(api.writes[0][0], "POST")
        api = FakeReader({issues: [mine, {**mine, "number": 8}]})
        with self.assertRaises(CONTRACT.ContractError):
            BACKLOG.announce(api, alerting=True, body="b", title=BACKLOG.ISSUE_TITLE)
        with self.assertRaises(CONTRACT.ContractError):
            BACKLOG.announce(
                FakeReader({issues: {}}),
                alerting=True,
                body="b",
                title=BACKLOG.ISSUE_TITLE,
            )

    def test_watch_counts_both_untagged_sources_and_unreleased_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            first = ledger.fragment(301, "first")
            ledger.tag("v0.1.10", first)
            ledger.fragment(302, "second")
            runs = (
                "/repos/owner/name/actions/workflows/platform-release.yml"
                "/runs?branch=main&per_page=1"
            )
            issues = "/repos/owner/name/issues?state=open&labels=%s&per_page=100" % (
                BACKLOG.ISSUE_LABELS[0]
            )
            api = FakeReader(
                {
                    "/repos/owner/name/releases/tags/v0.1.9": released("v0.1.9"),
                    runs: {"workflow_runs": []},
                    issues: [],
                }
            )
            # The fixture's commits are minutes old; look at them from two days
            # on so the 24-hour staleness rule is the thing under test.
            later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)
            with ledger.floor_patch():
                summary = BACKLOG.watch(ledger.root, "HEAD", api, later)
            self.assertIn("2 pending source release(s)", summary)
            self.assertIn("issue opened", summary)
            self.assertEqual([write[0] for write in api.writes], ["POST"])

    def test_the_watch_cli_reports_a_refusal_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            with mock.patch.dict(BACKLOG.os.environ, {"GITHUB_TOKEN": ""}):
                self.assertEqual(
                    BACKLOG.main(
                        ["watch", "--repository", str(ledger.root),
                         "--head", "HEAD", "--api-repository", "owner/name"]
                    ),
                    1,
                )

    def test_the_plan_cli_prints_the_derived_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Ledger(Path(temporary))
            first = ledger.fragment(301, "first")
            ledger.tag("v0.1.10", first)
            ledger.fragment(302, "second")
            stream = io.StringIO()
            with ledger.floor_patch(), mock.patch("sys.stdout", stream):
                code = BACKLOG.main(
                    ["plan", "--repository", str(ledger.root), "--head", "HEAD"]
                )
            self.assertEqual(code, 0)
            self.assertEqual(
                [edge["tag"] for edge in json.loads(stream.getvalue())], ["v0.1.11"]
            )


class ReaderTransportTests(unittest.TestCase):
    """The watchdog's transport refuses everything outside its narrow shape."""

    def reader(self):
        return BACKLOG.Reader("token", "owner/name")

    def test_construction_requires_a_token_and_one_repository(self):
        for token, repository in (("", "owner/name"), ("t", "owner"), ("t", 1)):
            with self.subTest(repository=repository), self.assertRaises(
                CONTRACT.ContractError
            ):
                BACKLOG.Reader(token, repository)

    def test_foreign_paths_budget_and_methods_refuse(self):
        # `ContractError` is also what a real HTTP failure raises, so the
        # refusal alone proves nothing: an admitted path would reach the
        # network and still land in `assertRaises`. Each refusal is therefore
        # asserted against `urlopen` never having been entered at all.
        api = self.reader()
        with mock.patch.object(BACKLOG.urllib.request, "urlopen") as opened:
            for path in ("repos/x", "/repos/../x", "/repos/x\n", "/repos/x#y"):
                with self.subTest(path=path), self.assertRaises(
                    CONTRACT.ContractError
                ):
                    api.get(path)
            with self.assertRaises(CONTRACT.ContractError):
                api.write("/repos/owner/name/issues", {}, method="DELETE")
            opened.assert_not_called()
        api.requests = BACKLOG.MAX_REQUESTS
        with mock.patch.object(
            BACKLOG.urllib.request, "urlopen"
        ) as opened, self.assertRaises(CONTRACT.ContractError):
            api.get("/repos/owner/name/issues")
        opened.assert_not_called()

    def test_absent_is_only_honoured_for_an_expected_absence(self):
        api = self.reader()
        error = urllib.error.HTTPError("u", 404, "missing", {}, None)
        with mock.patch.object(
            BACKLOG.urllib.request, "urlopen", side_effect=error
        ):
            self.assertIsNone(api.get("/repos/owner/name/x", absent=True))
        error = urllib.error.HTTPError("u", 404, "missing", {}, None)
        with mock.patch.object(
            BACKLOG.urllib.request, "urlopen", side_effect=error
        ), self.assertRaises(CONTRACT.ContractError):
            api.get("/repos/owner/name/x")
        error = urllib.error.HTTPError("u", 403, "denied", {}, None)
        with mock.patch.object(
            BACKLOG.urllib.request, "urlopen", side_effect=error
        ), self.assertRaises(CONTRACT.ContractError) as refusal:
            api.get("/repos/owner/name/x", absent=True)
        self.assertIn("403", str(refusal.exception))
        self.assertNotIn("token", str(refusal.exception))

    def test_an_oversize_response_refuses(self):
        api = self.reader()
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b"x" * (BACKLOG.MAX_RESPONSE_BYTES + 1)
        response.__enter__.return_value = response
        with mock.patch.object(
            BACKLOG.urllib.request, "urlopen", return_value=response
        ), self.assertRaises(CONTRACT.ContractError):
            api.get("/repos/owner/name/x")


class WiringTests(unittest.TestCase):
    """The workflow is the least-privileged shape the alert can have."""

    WORKFLOW = REPO_ROOT / ".github/workflows/release-backlog.yml"

    def test_the_workflow_holds_one_write_scope_and_no_publication_authority(self):
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions: {}\n", text)
        self.assertIn("      contents: read\n      issues: write\n", text)
        for forbidden in (
            "contents: write",
            "id-token: write",
            "actions: write",
            "packages: write",
            "create-github-app-token",
            "secrets.",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("release_backlog.py watch", text)

    def test_the_runbook_names_the_owner_command_the_watchdog_prints(self):
        runbook = (REPO_ROOT / "docs/runbooks/platform-source-releases.md").read_text(
            encoding="utf-8"
        )
        self.assertTrue(BACKLOG.OWNER_COMMAND in runbook, "runbook omits the command")
        self.assertTrue(BACKLOG.ISSUE_TITLE in runbook, "runbook omits the alert")


if __name__ == "__main__":
    unittest.main()
