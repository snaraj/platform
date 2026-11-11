"""Pin when CI scans the fixed proxy image (issue #456), by running the real step.

The workflow step's own shell body is executed in a disposable repository with
the real scope helper and a stub scan that records it ran, so the tests prove
both directions of the path condition and that a skip ends the step in
success: the required job name and the publisher's exact-step admission
(``MAIN_CI_REQUIRED_STEPS``) both depend on that step concluding success.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT, hermetic_git_environment, load_script

SCOPE = load_script("ci/proxy_image_scan_scope.py")
STEP = "Scan the pinned obsync proxy image"


def workflow(name):
    parsed = subprocess.run(["conftest", "parse", str(REPO_ROOT / ".github/workflows" / name)],
                            capture_output=True, text=True, check=True, timeout=30).stdout
    return json.loads(parsed)


@unittest.skipUnless(shutil.which("conftest"), "conftest parses the workflow YAML")
class WorkflowStepTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.env = hermetic_git_environment(identity=("Example", "example@example.invalid"))
        self.git("init", "-q", "-b", "main")
        helper = self.root / "scripts/ci/proxy_image_scan_scope.py"
        helper.parent.mkdir(parents=True)
        shutil.copy(REPO_ROOT / "scripts/ci/proxy_image_scan_scope.py", helper)
        # The stub stands in for Trivy: it only records that the scan ran.
        stub = self.root / "scripts/ci/scan-proxy-image.sh"
        stub.write_text("#!/usr/bin/env bash\ntouch scanned\n")
        stub.chmod(0o755)
        (self.root / "versions.env").write_text("OBSYNC_TLS_PROXY_IMAGE=example\n")
        (self.root / "README.md").write_text("docs\n")
        self.git("add", "--all")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        job = workflow("pull-request.yml")["jobs"]["repository-and-infrastructure"]
        self.assertNotIn("if", job)
        steps = [step for step in job["steps"] if step.get("name") == STEP]
        self.assertEqual(len(steps), 1)
        self.assertNotIn("if", steps[0])
        self.body = steps[0]["run"]

    def git(self, *args):
        return subprocess.run(["git", "-c", "commit.gpgSign=false", *args], cwd=self.root, env=self.env,
                              check=True, capture_output=True, text=True).stdout.strip()

    def change(self, path, text="changed\n"):
        self.git("checkout", "-q", "--detach", self.base)
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git("add", "--all")
        self.git("commit", "-qm", f"change {path}")
        return self.git("rev-parse", "HEAD")

    def step(self, event, base, head):
        (self.root / "scanned").unlink(missing_ok=True)
        env = dict(self.env, GITHUB_EVENT_NAME=event, PR_BASE_SHA="", PR_HEAD_SHA="", PUSH_BASE_SHA="", PUSH_HEAD_SHA="")
        env.update({"pull_request": {"PR_BASE_SHA": base, "PR_HEAD_SHA": head},
                    "push": {"PUSH_BASE_SHA": base, "PUSH_HEAD_SHA": head}}.get(event, {}))
        done = subprocess.run(["bash", "-e", "-c", self.body], cwd=self.root, env=env, capture_output=True, text=True,
                              timeout=60)
        return done.returncode, (self.root / "scanned").exists(), done.stdout

    def test_unrelated_changes_skip_in_success_and_image_changes_scan(self):
        docs = self.change("README.md")
        pin = self.change("versions.env", "OBSYNC_TLS_PROXY_IMAGE=other\n")
        manifest = self.change("kubernetes/platform/obsync-tls-proxy/deployment.yaml")
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                status, scanned, output = self.step(event, self.base, docs)
                self.assertEqual((status, scanned), (0, False))
                self.assertIn("SKIP proxy image scan", output)
                self.assertEqual(self.step(event, self.base, pin)[:2], (0, True))
                self.assertEqual(self.step(event, self.base, manifest)[:2], (0, True))
        self.assertEqual(self.step("workflow_dispatch", "", "")[:2], (0, True), "a manual run always scans")
        self.assertEqual(self.step("push", "0" * 40, docs)[:2], (0, True), "no previous commit means scan")
        status, scanned, _ = self.step("pull_request", "not-a-sha", docs)
        self.assertNotEqual(status, 0, "an unreadable range fails the step, never skips it")
        self.assertFalse(scanned)

    def test_the_scheduled_run_scans_main_unconditionally(self):
        steps = workflow("scheduled-security.yml")["jobs"]["scan"]["steps"]
        self.assertIn({"name": STEP, "run": "./scripts/ci/scan-proxy-image.sh"}, steps)
        self.assertNotIn("if", workflow("scheduled-security.yml")["jobs"]["scan"])


class ScopeTests(unittest.TestCase):
    def test_every_input_that_defines_the_image_or_its_scan_triggers_it(self):
        for path in sorted(SCOPE.TRIGGER_FILES) + ["kubernetes/platform/obsync-tls-proxy/kustomization.yaml"]:
            with self.subTest(path=path):
                self.assertTrue(SCOPE.needs_scan(["README.md", path]))
        for paths in ([], ["README.md"], ["docs/versions.env"], ["kubernetes/platform/obsync-tls-proxy-other/x.yaml"],
                      ["scripts/ci/scan-proxy-image.sh.bak"]):
            with self.subTest(paths=paths):
                self.assertFalse(SCOPE.needs_scan(paths))

    def test_the_trigger_list_names_files_that_exist_or_that_trivy_reads(self):
        for path in SCOPE.TRIGGER_FILES - {".trivyignore", ".trivyignore.yaml", "trivy.yaml"}:
            with self.subTest(path=path):
                self.assertTrue((REPO_ROOT / path).is_file(), path)
        self.assertTrue((REPO_ROOT / SCOPE.TRIGGER_PREFIXES[0]).is_dir())

    def test_malformed_arguments_fail(self):
        for argv in (["scope"], ["scope", "a" * 40], ["scope", "a" * 39, "b" * 40], ["scope", "A" * 40, "b" * 40]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(SCOPE.main(argv), 1)
            self.assertEqual(error.getvalue(), "proxy image scan scope: ValueError\n")


if __name__ == "__main__":
    unittest.main()
