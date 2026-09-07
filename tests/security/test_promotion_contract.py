"""Pin the retired image-promotion path and its immutable successor."""

import shutil
import subprocess
import unittest
from pathlib import Path

from .support import load_script, required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMOTION = REPO_ROOT / "scripts" / "promote-image.sh"
ROLLBACK = REPO_ROOT / "docs" / "runbooks" / "image-rollback.md"
BASH = shutil.which("bash")
STATE = load_script("validate_release_state.py")
SIGNATURE = load_script("validate_signature_policy.py")


class RetiredPromotionContractTests(unittest.TestCase):
    """The obsolete override workflow must be impossible to invoke."""

    def test_script_is_an_unconditional_local_refusal(self):
        script = PROMOTION.read_text(encoding="utf-8")
        self.assertTrue(script.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("promote-image: RETIRED", script)
        self.assertTrue(script.rstrip().endswith("exit 1"))

        executable = "\n".join(
            line for line in script.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        for forbidden in (
            "command -v", "git ", "gh ", "curl ", "wget ", "oras ",
            "cosign ", "docker ", "helm ", "kubectl ", "python",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, executable)

    @unittest.skipUnless(BASH, "bash is required")
    def test_every_argument_shape_fails_before_tool_or_network_use(self):
        expected = (
            "promote-image: RETIRED; review an exact chart-release annotation "
            "and OCI manifest digest pair in source.yaml\n"
        )
        for arguments in ((), ("--help",), ("naranjo-online", "v0.1.1", "sha256:" + "a" * 64)):
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [required_tool(BASH, "bash is required"), str(PROMOTION), *arguments],
                    capture_output=True,
                    text=True,
                    check=False,
                    env={"PATH": "", "LC_ALL": "C"},
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, expected)

    def test_releases_have_no_second_image_authority(self):
        """No workload release may carry image identity, whatever else it carries.

        The two sites carry exactly one readiness scalar. `obsidian` carries the
        obsync chart's closed deployment binding, which is larger — and this is
        the assertion that matters for it: whatever a values block states, it
        never states a repository, tag or digest. The signed chart is the sole
        image-identity carrier (ADR 0016), and `scripts/validate_release_state.py`
        pins each block line for line.
        """

        for slug in SIGNATURE.CHART_REPOSITORIES:
            with self.subTest(slug=slug):
                state = STATE.load_helm_release(slug, REPO_ROOT)
                if slug in SIGNATURE.PENDING_CHART_RELEASES:
                    self.assertNotEqual(state.values, {})
                else:
                    self.assertEqual(state.values, {("deploymentReady",): "true"})
                for forbidden in ("image:", "repository:", "tag:", "digest:"):
                    self.assertNotIn(forbidden, state.values_text)

    def test_sources_select_only_the_reviewed_nonzero_digest(self):
        released = set(SIGNATURE.CHART_REPOSITORIES) - set(
            SIGNATURE.PENDING_CHART_RELEASES
        )
        for slug in sorted(released):
            with self.subTest(slug=slug):
                tag, digest = SIGNATURE.chart_source_release(slug)
                source = (
                    REPO_ROOT / "kubernetes" / "websites" / slug / "source.yaml"
                ).read_text(encoding="utf-8")
                self.assertIn(
                    'platform.snaraj.dev/chart-release: "{}"'.format(tag), source
                )
                self.assertIn("  ref:\n    digest: {}\n".format(digest), source)
                self.assertNotEqual(digest, "sha256:" + "0" * 64)
                self.assertNotRegex(source, r"(?m)^    (?:tag|semver):")

    def test_a_pending_source_selects_only_the_sentinel_and_no_selector(self):
        """The other half of the rule above, for a workload with no release yet.

        A pending workload must carry the all-zero digest — which resolves to
        nothing, so it deploys nothing — and must still refuse a tag or semver
        selector, because the way a placeholder turns into a live deploy is a
        mutable selector quietly replacing it.
        """

        for slug in sorted(SIGNATURE.PENDING_CHART_RELEASES):
            with self.subTest(slug=slug):
                tag, digest = SIGNATURE.chart_source_release(slug)
                source = (
                    REPO_ROOT / "kubernetes" / "websites" / slug / "source.yaml"
                ).read_text(encoding="utf-8")
                self.assertEqual(digest, "sha256:" + "0" * 64)
                self.assertIn(
                    'platform.snaraj.dev/chart-release: "{}"'.format(tag), source
                )
                self.assertIn("  ref:\n    digest: {}\n".format(digest), source)
                self.assertNotRegex(source, r"(?m)^    (?:tag|semver):")
                # And it must be reconciled to nothing until then: a pending
                # workload whose HelmRelease was live would be asking
                # helm-controller to install an artifact that cannot exist.
                self.assertTrue(STATE.load_helm_release(slug, REPO_ROOT).suspended)

    def test_rollback_requires_a_new_exact_pair_and_has_no_fallback(self):
        runbook = ROLLBACK.read_text(encoding="utf-8")
        for requirement in (
            "new, separately reviewed",
            "nonzero OCI manifest digest",
            "Repeat resolution after",
            "If the older tag or exact manifest digest is deleted, moved, unavailable",
            "Do not select another available tag or digest",
            "exact chart-manifest digest pair",
            "no image repository, tag, or digest",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, runbook)

if __name__ == "__main__":
    unittest.main()
