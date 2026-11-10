"""Pin `scripts/ready_check.py`: the ReadyRuleTests cases that survived the promoter's deleted auto-Ready machinery, on the one-APPROVE rule."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .support import hermetic_git_environment, load_script

MODULE = load_script("ready_check.py")
HEAD = "1" * 40
# The metadata a real reviewable pull request carries; each hostile case below
# changes exactly one field of it, so the blocker it proves is unambiguous.
LABELS = ["agent-authored", "security", "cybersecurity-review-requested"]
OPEN = {"state": "open", "base_ref": "main", "default_branch": "main"}
# Distinct from None, which is itself a case under test: unreadable labels.
DEFAULT = object()


def decide(labels=DEFAULT, comments=DEFAULT, check_runs=DEFAULT, behind_by=0, **overrides):
    """`ready_decision` on an otherwise-eligible pull request."""
    return MODULE.ready_decision(
        HEAD,
        LABELS if labels is DEFAULT else labels,
        [comment()] if comments is DEFAULT else comments,
        checks() if check_runs is DEFAULT else check_runs,
        behind_by,
        **dict(OPEN, **overrides),
    )


def comment(head=HEAD, verdict="APPROVE", lane="Opus5", login=MODULE.REVIEWS_APP, uid=MODULE.REVIEWS_APP_USER_ID, kind="Bot", app=MODULE.REVIEWS_APP_ID):
    body = f"HEAD: {head}\nVERDICT: {verdict}\n\nMutation matrix and claim audit: supported.\n\n- {lane} (adversarial reviewer)\n"
    return {"user": {"login": login, "id": uid, "type": kind}, "performed_via_github_app": {"id": app}, "body": body}


def checks(conclusion="success", app=MODULE.REQUIRED_CHECK_APP, security="success"):
    return ([{"name": n, "status": "completed", "conclusion": conclusion, "app": {"slug": app}} for n in MODULE.REQUIRED_CHECKS]
            + [{"name": n, "status": "completed", "conclusion": security, "app": {"slug": security_app}}
               for n, security_app in MODULE.REQUIRED_SECURITY_CHECKS.items()]
            + [{"name": "optional-pr-job", "status": "completed", "conclusion": "skipped", "app": {"slug": "github-actions"}}])


class ReadyRuleTests(unittest.TestCase):
    def test_one_exact_head_approval_from_the_app_with_green_checks_is_eligible(self):
        self.assertEqual(decide(comments=[comment(lane="Opus 5")]), (["opus5"], ["security"], []))
        self.assertEqual(MODULE.ACCEPTABLE_CONCLUSIONS, frozenset({"success", "neutral", "skipped"}), "the allowlist is the contract; widen it only with a case here")

    def test_every_receipt_evasion_leaves_the_head_unapproved(self):
        # Another head or poster, the bot login without the bot's own id or
        # App, a user account wearing it, a loose verdict, an unsigned lane.
        for override in ({"head": "2" * 40}, {"login": "snaraj"}, {"uid": 1}, {"app": None}, {"kind": "User"}, {"verdict": "APPROVE with caveats"}, {"lane": " "}):
            with self.subTest(override=override):
                self.assertIn("no adversarial APPROVE receipt binds this head", decide(comments=[comment(**override)])[2])

    def test_every_single_failure_blocks(self):
        good = [comment()]
        for reason, state in {
            "a REQUEST-CHANGES receipt": {"comments": good + [comment(verdict="REQUEST-CHANGES", lane="Codex")]},
            "requires-review is still armed": {"labels": LABELS + ["requires-review"]},
            "was not produced by": {"check_runs": checks(app="mallory-ci")},
            "appears 2 times": {"check_runs": checks() + [dict(checks()[0], app={"slug": "mallory-ci"})]},
            "has not succeeded": {"check_runs": checks("failure")},
            "appears 0 times": {"check_runs": []},
            "CodeQL ended failure": {"check_runs": [dict(check, conclusion="failure") if check["name"] == "CodeQL" else check for check in checks()]},
            "behind main": {"behind_by": 3},
            "base freshness is unknown": {"behind_by": None},
        }.items():
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(**state)[2]), reason)

    def test_a_check_still_running_at_this_head_is_a_blocker(self):
        # Finding 3: only completed checks were judged, so an otherwise-valid
        # snapshot carrying a pending CodeQL run was ELIGIBLE. A run with no
        # verdict yet cannot be green, and it can still fail.
        for status in ("queued", "in_progress", "waiting", None):
            with self.subTest(status=status):
                pending = checks()[:-1] + [{"name": "optional-pr-job", "status": status, "conclusion": None, "app": {"slug": "github-actions"}}]
                self.assertIn(f"a check at this head has not finished: optional-pr-job is {status}", decide(check_runs=pending)[2])
        # The same input, with that one run completed, has no blocker at all.
        self.assertEqual(decide(check_runs=checks())[2], [])

    def test_python_codeql_is_exactly_one_successful_security_check(self):
        security_name, security_app = next(iter(MODULE.REQUIRED_SECURITY_CHECKS.items()))
        baseline = checks()
        security = next(check for check in baseline if check["name"] == security_name)
        without = [check for check in baseline if check["name"] != security_name]
        self.assertTrue(any(f"required security check {security_name} appears 0 times" in blocker for blocker in decide(check_runs=without)[2]))
        foreign_language = without + [dict(security, name="analyze (go, autobuild)")]
        self.assertTrue(any(f"required security check {security_name} appears 0 times" in blocker for blocker in decide(check_runs=foreign_language)[2]))
        self.assertTrue(any(f"required security check {security_name} appears 2 times" in blocker for blocker in decide(check_runs=baseline + [security])[2]))
        foreign = [dict(check, app={"slug": "github-advanced-security"}) if check["name"] == security_name else check for check in baseline]
        self.assertTrue(any(f"required security check {security_name} was not produced by {security_app}" in blocker for blocker in decide(check_runs=foreign)[2]))
        for conclusion in ("neutral", "skipped", "failure", "cancelled", None):
            with self.subTest(conclusion=conclusion):
                changed = [dict(check, conclusion=conclusion) if check["name"] == security_name else check for check in baseline]
                self.assertTrue(any(f"required security check {security_name} has not succeeded" in blocker for blocker in decide(check_runs=changed)[2]))
        self.assertEqual(decide(check_runs=baseline)[2], [])

    def test_aggregate_codeql_neutral_and_skipped_are_not_security_success(self):
        for conclusion in ("neutral", "skipped"):
            with self.subTest(conclusion=conclusion):
                changed = [dict(check, conclusion=conclusion) if check["name"] == "CodeQL" else check for check in checks()]
                self.assertTrue(any("required security check CodeQL has not succeeded" in blocker for blocker in decide(check_runs=changed)[2]))
        self.assertEqual(decide(check_runs=checks())[2], [])


class WrongPullRequestTests(unittest.TestCase):
    """Finding 1: state, base and tier decide WHICH pull request this is.

    Each case changes exactly one field of an otherwise-eligible pull request,
    proves the exact blocker, and proves the same input goes green once that
    one condition is repaired — so none of them can pass vacuously.
    """

    def test_each_wrong_pull_request_is_blocked_and_repairable(self):
        for reason, broken, repaired in (
            ("the pull request is not open (state: closed)", {"state": "closed"}, {"state": "open"}),
            ("the pull request is not open (state: merged)", {"state": "merged"}, {"state": "open"}),
            ("the pull request is not open (state: unreadable)", {"state": None}, {"state": "open"}),
            ("targets not-main, not the default branch main", {"base_ref": "not-main"}, {"base_ref": "main"}),
            ("base branch is missing or unreadable", {"base_ref": None}, {"base_ref": "main"}),
            ("base branch is missing or unreadable", {"default_branch": None}, {"default_branch": "main"}),
        ):
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(**broken)[2]), reason)
                self.assertEqual(decide(**dict(broken, **repaired))[2], [], "repairing the one field must clear every blocker")

    def test_a_stale_base_names_the_branch_it_is_behind(self):
        self.assertIn("branch is 3 commit(s) behind main", decide(behind_by=3)[2])
        self.assertEqual(decide(behind_by=0)[2], [])

    def test_missing_or_contradictory_metadata_is_a_blocker(self):
        for reason, labels in (
            ("carries no tier label", ["agent-authored"]),
            ("missing the agent-authored umbrella label", ["security", "cybersecurity-review-requested"]),
            ("labels are missing or unreadable", None),
            ("conflicting tier labels", ["agent-authored", "security"]),
            ("conflicting tier labels", ["agent-authored", "docs", "cybersecurity-review-requested"]),
        ):
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in b for b in decide(labels=labels)[2]), reason)
        # The documentation tier needs neither security label, and passes.
        self.assertEqual(decide(labels=["agent-authored", "docs"])[2], [])

    def test_the_tier_labels_are_reported_beside_the_approving_lanes(self):
        lanes, tiers, blockers = decide(labels=["agent-authored", "docs", "tests"])
        self.assertEqual((lanes, tiers, blockers), (["opus5"], ["docs", "tests"], []))
        # The lane-to-tier judgment is deliberately NOT made here; the module
        # says so where a reader of its output will see it.
        self.assertIn("coordinator", MODULE.__doc__)


class BodyBindingTests(unittest.TestCase):
    """A receipt may bind the pull request body it audited (issue #309): the
    body is same-head-mutable, so the rule recomputes the digest live."""

    BODY = "Promote naranjo.online 0.1.99\n\nAccounting: 9 files, +1 / -1\n"

    @staticmethod
    def bound(body_text, verdict="APPROVE", lane="Promoter"):
        receipt = comment(verdict=verdict, lane=lane)
        receipt["body"] = receipt["body"].replace(
            f"VERDICT: {verdict}\n", f"VERDICT: {verdict}\n{MODULE.BODY_BINDING}{MODULE.body_digest(body_text)}\n", 1
        )
        return receipt

    def test_the_digest_is_stable_across_newline_normalisation(self):
        self.assertEqual(MODULE.body_digest(self.BODY), MODULE.body_digest(self.BODY.replace("\n", "\r\n")))
        self.assertEqual(MODULE.body_digest(self.BODY), MODULE.body_digest("\n\n" + self.BODY + "\n"))
        self.assertNotEqual(MODULE.body_digest(self.BODY), MODULE.body_digest(self.BODY + "one more sentence"))
        self.assertEqual(MODULE.body_digest(None), MODULE.body_digest(""))

    def test_a_receipt_bound_to_the_live_body_is_eligible(self):
        lanes, _, blockers = decide(comments=[self.bound(self.BODY)], body=self.BODY)
        self.assertEqual(blockers, [])
        self.assertEqual(lanes, ["promoter"])

    def test_a_body_edited_after_the_receipt_withholds_ready(self):
        for edited in (self.BODY + "One more sentence.\n", self.BODY.replace("0.1.99", "0.1.98"), "", None):
            with self.subTest(edited=edited):
                lanes, _, blockers = decide(comments=[self.bound(self.BODY)], body=edited)
                self.assertEqual(lanes, [], "a receipt bound to another body approves nothing")
                self.assertIn("a receipt at this head binds a different pull request body; the body was edited after the receipt", blockers)
                self.assertIn("no adversarial APPROVE receipt binds this head", blockers)

    def test_an_unbound_receipt_is_read_as_before(self):
        # A human reviewer's receipt states no body digest, and the rule does
        # not invent one: the head is what it binds, exactly as before.
        lanes, _, blockers = decide(body=self.BODY + "edited later")
        self.assertEqual(blockers, [])
        self.assertEqual(lanes, ["opus5"])

    def test_a_mismatched_binding_is_never_counted_as_any_verdict(self):
        # A REQUEST-CHANGES bound to a stale body is a blocker on its own
        # terms, not silently a second REQUEST-CHANGES.
        lanes, _, blockers = decide(comments=[self.bound("stale", verdict="REQUEST-CHANGES")], body=self.BODY)
        self.assertEqual(lanes, [])
        self.assertIn("a receipt at this head binds a different pull request body; the body was edited after the receipt", blockers)
        self.assertNotIn("a REQUEST-CHANGES receipt binds this head", blockers)


class CarryTests(unittest.TestCase):
    """Issue #456: an App APPROVE carries to a re-cut head only when the change
    is byte-identical, the old head is GitHub-recorded, and this head is green.

    The patch identities are computed by real Git on a disposable repository:
    B1 -> OLD (the reviewed change), B1 -> B2 (main moved), B2 -> NEW (the
    same change re-cut), plus near-identical variants that must not carry.
    """

    # Both functions share every line within three of the insertion point, so
    # git's default-context patch-id cannot tell which one a hunk lands in.
    BODY = "    pass\n    x = 1\n    y = 2\n    z = 3\n    return x\n    # end\n    # end\n    # end\n"
    FILE = "def first():\n" + BODY + "def second():\n" + BODY

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        env = hermetic_git_environment(identity=("Example", "example@example.invalid"))

        def git(*args):
            return subprocess.run(["git", "-c", "commit.gpgSign=false", *args], cwd=self.root, env=env,
                                  check=True, capture_output=True, text=True).stdout.strip()

        def commit(base, name, text, mode=None):
            git("checkout", "-q", "--detach", base)
            (self.root / "a.py").write_text(text)
            if mode:
                (self.root / "a.py").chmod(mode)
            git("commit", "-qam", name)
            return git("rev-parse", "HEAD")

        git("init", "-q", "-b", "main")
        (self.root / "a.py").write_text(self.FILE)
        (self.root / "b.txt").write_text("base\n")
        git("add", "--all")
        git("commit", "-qm", "base")
        self.b1 = git("rev-parse", "HEAD")
        change = self.FILE.replace("    y = 2\n", "    y = 2\n    audit()\n", 1)
        self.old = commit(self.b1, "change", change)
        git("checkout", "-q", "--detach", self.b1)
        (self.root / "b.txt").write_text("main moved\n")
        git("commit", "-qam", "main moved")
        self.b2 = git("rev-parse", "HEAD")
        self.new = commit(self.b2, "re-cut", change)
        self.one_line = commit(self.b2, "one line", change.replace("audit()", "audit(False)"))
        self.reindented = commit(self.b2, "indent", change.replace("    audit()", "        audit()"))
        cut = self.FILE.rindex("    y = 2\n") + len("    y = 2\n")
        self.elsewhere = commit(self.b2, "elsewhere", self.FILE[:cut] + "    audit()\n" + self.FILE[cut:])
        self.executable = commit(self.b2, "mode", change, mode=0o755)

    def identity(self, base, head):
        return MODULE.patch_identity(base, head, root=self.root)

    def test_patch_identity_is_byte_exact_and_whole_file(self):
        original = self.identity(self.b1, self.old)
        self.assertRegex(original, r"^[0-9a-f]{40}$")
        self.assertEqual(self.identity(self.b2, self.new), original, "the same change re-cut on a moved base")
        for name, head in (("one changed line", self.one_line), ("re-indented line", self.reindented),
                           ("same hunk in another function", self.elsewhere), ("mode change", self.executable)):
            with self.subTest(name):
                self.assertNotEqual(self.identity(self.b2, head), original)
        # The reason for whole-file context: at git's default three lines the
        # hunk replayed in the other function is indistinguishable.
        default = [subprocess.run(["git", "diff", "--binary", "--full-index", base, head], cwd=self.root,
                                  capture_output=True, check=True).stdout for base, head in
                   ((self.b1, self.old), (self.b2, self.elsewhere))]
        ids = [subprocess.run(["git", "patch-id", "--verbatim"], cwd=self.root, input=diff, capture_output=True,
                              check=True).stdout.split()[0] for diff in default]
        self.assertEqual(ids[0], ids[1])
        self.assertIsNone(self.identity(self.b1, self.b1))
        with self.assertRaisesRegex(MODULE.Refusal, "not available locally"):
            self.identity(self.b1, "e" * 40)

    def carry(self, comments, head, recorded=None):
        pull = {"head": head, "comments": comments, "baseRef": "main", "mergeBase": self.b2}
        real = MODULE.patch_identity
        with patch.object(MODULE, "gh", return_value={"merge_base_commit": {"sha": self.b1}}), \
                patch.object(MODULE, "recorded_heads", return_value={self.old} if recorded is None else recorded), \
                patch.object(MODULE, "patch_identity", lambda base, tip: real(base, tip, root=self.root)):
            return MODULE.carried_lanes("snaraj/platform", 7, pull, [7])

    def test_an_identical_re_cut_keeps_the_app_approval_and_nothing_else_does(self):
        lanes, notes = self.carry([comment(head=self.old)], self.new)
        self.assertEqual(lanes, ["opus5"])
        self.assertEqual(MODULE.ready_decision(self.new, LABELS, [comment(head=self.old)], checks(), 0,
                                               carried=lanes, **OPEN), (["opus5"], ["security"], []))
        for name, comments, head, recorded, reason in (
            ("one changed line", [comment(head=self.old)], self.one_line, None, "not byte-identical"),
            ("re-indented line", [comment(head=self.old)], self.reindented, None, "not byte-identical"),
            ("a non-App author", [comment(head=self.old, login="snaraj", uid=39077795, kind="User", app=None)],
             self.new, None, "no App-posted receipt"),
            ("the bot login without the App", [comment(head=self.old, app=None)], self.new, None, "no App-posted receipt"),
            ("a later REQUEST-CHANGES", [comment(head=self.old), comment(head=self.one_line, verdict="REQUEST-CHANGES")],
             self.new, None, "not an APPROVE"),
            ("an unrecorded old head", [comment(head=self.old)], self.new, {self.new}, "recorded head history"),
        ):
            with self.subTest(name):
                lanes, notes = self.carry(comments, head, recorded)
                self.assertEqual(lanes, [])
                self.assertIn(reason, notes[0])
                self.assertIn("no adversarial APPROVE receipt binds this head",
                              MODULE.ready_decision(head, LABELS, comments, checks(), 0, carried=lanes, **OPEN)[2])

    def test_a_carried_approval_never_waives_this_heads_checks_or_verdicts(self):
        carried = self.carry([comment(head=self.old)], self.new)[0]
        for name, comments, check_runs, reason in (
            ("required checks missing", [], [], "required check repository-and-infrastructure appears 0 times"),
            ("a required check failed", [], checks("failure"), "has not succeeded at this head"),
            ("REQUEST-CHANGES at this head", [comment(head=self.new, verdict="REQUEST-CHANGES")], checks(),
             "a REQUEST-CHANGES receipt binds this head"),
        ):
            with self.subTest(name):
                blockers = MODULE.ready_decision(self.new, LABELS, comments, check_runs, 0, carried=carried, **OPEN)[2]
                self.assertTrue(any(reason in blocker for blocker in blockers), blockers)

    def test_carry_verdict_names_each_refusal(self):
        last = (self.old, "APPROVE", "opus5", False)
        self.assertIsNone(MODULE.carry_verdict(self.new, last, {self.old}, "p", "p"))
        for name, args, reason in (
            ("no receipt", (None, {self.old}, "p", "p"), "no App-posted receipt"),
            ("same head", ((self.new, "APPROVE", "opus5", False), {self.new}, "p", "p"), "already binds this head"),
            ("request changes", ((self.old, "REQUEST-CHANGES", "opus5", False), {self.old}, "p", "p"), "not an APPROVE"),
            ("body bound", ((self.old, "APPROVE", "opus5", True), {self.old}, "p", "p"), "binds a pull request body"),
            ("unrecorded", (last, set(), "p", "p"), "recorded head history"),
            ("different patch", (last, {self.old}, "p", "q"), "not byte-identical"),
            ("empty patch", (last, {self.old}, None, None), "not byte-identical"),
        ):
            with self.subTest(name):
                self.assertIn(reason, MODULE.carry_verdict(self.new, *args))
