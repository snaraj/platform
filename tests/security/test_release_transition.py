"""Exercise safe mixed GitOps release-state transitions."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from .support import load_script


REPO_ROOT = Path(__file__).resolve().parents[2]
TRANSITION = load_script("validate_release_transition.py")

RELEASE_FILES = (
    "kubernetes/websites/naranjo-online/release.yaml",
    "kubernetes/websites/lidersea-com/release.yaml",
    "kubernetes/websites/obsidian/release.yaml",
    "kubernetes/platform/cloudflare-public/release/release.yaml",
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml",
)
# Every workload the classifier walks. `obsidian` is in it because the
# classifier selects the release MODE, and release mode is what turns the
# release-conftest suite on: a workload the classifier could not see could sit
# suspended behind a placeholder chart digest while the tree claimed `release`,
# a mode no render can then pass (issue #348).
SITE_FILES = {
    "naranjo-online": "kubernetes/websites/naranjo-online/release.yaml",
    "lidersea-com": "kubernetes/websites/lidersea-com/release.yaml",
    "obsidian": "kubernetes/websites/obsidian/release.yaml",
}


class ReleaseTransitionTests(unittest.TestCase):
    """Reject unsafe mixtures while allowing staged activation and rollback."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in RELEASE_FILES:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / relative, destination)
        self.normalize_scaffold_baseline()

    def tearDown(self):
        self.temporary.cleanup()

    def normalize_scaffold_baseline(self):
        """Suspend the site HelmReleases; direct reconcilers remain active."""

        for relative in SITE_FILES.values():
            path = self.root / relative
            text = path.read_text(encoding="utf-8")
            # `obsidian` is already committed suspended, so this normalizes
            # rather than flips: the assertion below is what proves each
            # fixture reached the one staged state regardless of its start.
            text = text.replace("  suspend: false\n", "  suspend: true\n")
            self.assertEqual(text.count("  suspend: true\n"), 1, relative)
            with path.open("w", encoding="utf-8", newline="\n") as output:
                output.write(text)

    def replace_once(self, relative, before, after):
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(before), 1, relative)
        with path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(text.replace(before, after))

    def set_suspended(self, relative, suspended):
        before = "  suspend: false\n" if suspended else "  suspend: true\n"
        after = "  suspend: true\n" if suspended else "  suspend: false\n"
        self.replace_once(relative, before, after)

    def activate_site(self, name):
        self.set_suspended(SITE_FILES[name], False)

    def configure_cloudflare_revision(self, *, sites=None):
        """Resolve each named connector's own revision (default: all of them).

        Every website's connector owns its revision, so the staged/active
        fixtures must resolve both. Passing a subset builds the half-configured
        state the classifier refuses.
        """

        if sites is None:
            sites = TRANSITION.STATE.PUBLIC_CONNECTOR_SITES
        path = self.root / (
            "kubernetes/platform/cloudflare-public/release/release.yaml"
        )
        text = path.read_text(encoding="utf-8")
        for site in sites:
            before = "      {}:\n        tokenRevision: not-configured\n".format(site)
            self.assertEqual(text.count(before), 1, site)
            text = text.replace(
                before,
                "      {}:\n        tokenRevision: rev-reviewed-test\n".format(site),
            )
        with path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(text)

    def activate_both_sites(self):
        for site in SITE_FILES:
            self.activate_site(site)

    def test_exact_staged_state_is_a_direct_reconciliation_transition(self):
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(
            (
                plan.naranjo_online,
                plan.lidersea_com,
                plan.obsidian,
                plan.cloudflare_public,
            ),
            ("staged", "staged", "staged", "initial"),
        )
        self.assertTrue(plan.any_website_active)
        self.assertTrue(plan.any_workload_active)
        self.assertFalse(plan.naranjo_parent_suspended)
        self.assertFalse(plan.lidersea_parent_suspended)
        self.assertFalse(plan.obsidian_parent_suspended)

    def test_extra_site_value_is_rejected(self):
        self.replace_once(
            SITE_FILES["naranjo-online"],
            "    deploymentReady: true\n",
            "    deploymentReady: true\n    image:\n      digest: sha256:"
            + ("a" * 64)
            + "\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_staged_sites_keep_the_direct_safety_envelope(self):
        """A direct Kustomization stays active while its HelmRelease is staged."""

        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "staged")
        self.assertTrue(plan.any_website_active)
        self.assertTrue(plan.any_workload_active)

    def test_both_active_sites_remain_outside_the_cloudflare_loop(self):
        self.activate_both_sites()
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(
            (
                plan.naranjo_online,
                plan.lidersea_com,
                plan.obsidian,
                plan.cloudflare_public,
            ),
            ("active", "active", "active", "initial"),
        )
        self.assertTrue(plan.platform_suspended)
        self.assertTrue(plan.any_website_active)

    def test_committed_sites_are_active_without_an_admission_dependency(self):
        """The safe live bridge has no retired controller prerequisite."""

        plan = TRANSITION.classify(REPO_ROOT)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(
            (
                plan.naranjo_online,
                plan.lidersea_com,
                plan.obsidian,
                plan.cloudflare_public,
            ),
            ("active", "active", "staged", "initial"),
        )
        self.assertTrue(plan.platform_suspended)

    def test_suspending_one_active_site_is_a_safe_transition(self):
        self.activate_both_sites()
        self.set_suspended(SITE_FILES["naranjo-online"], True)
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "staged")
        self.assertEqual(plan.lidersea_com, "active")
        self.assertEqual(plan.obsidian, "active")

    def test_the_third_workload_is_parsed_and_classified_like_the_two_sites(self):
        """obsidian carries a phase of its own, and the classifier earns it.

        `release` mode is what turns the release-conftest suite on, and that
        suite refuses a suspended HelmRelease outright, so a workload the
        classifier could not see could sit staged behind a placeholder chart
        digest while the mode said otherwise. The last assertion is what makes
        the first two non-vacuous: an unreviewed value in this release is
        refused exactly as one in a site release is, which a classifier that
        skipped the file could not do.
        """

        self.assertEqual(TRANSITION.classify(self.root).obsidian, "staged")
        self.activate_site("obsidian")
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.obsidian, "active")
        self.assertEqual(
            (plan.naranjo_online, plan.lidersea_com), ("staged", "staged")
        )
        self.replace_once(
            SITE_FILES["obsidian"],
            "    deploymentReady: false\n",
            "    deploymentReady: false\n    unreviewed: true\n",
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cloudflare_cannot_enter_the_selected_site_loop(self):
        self.set_suspended(
            "kubernetes/platform/cloudflare-public/release/release.yaml", False
        )
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_half_configured_connector_revisions_are_rejected(self):
        """One connector staged while the other still carries a sentinel is
        not a safe intermediate: each Tunnel's revision is its own, so a mixed
        pair means a rotation or staging step was left half done."""

        for index, site in enumerate(TRANSITION.STATE.PUBLIC_CONNECTOR_SITES):
            with self.subTest(configured=site):
                if index:
                    self.tearDown()
                    self.setUp()
                self.configure_cloudflare_revision(sites=(site,))
                with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
                    TRANSITION.classify(self.root)

    def test_public_release_inventory_must_stay_secretless(self):
        """Re-listing anything beside the two reviewed resources is refused.

        This is the whole mechanism keeping a Secret — or a file that renders
        one — out of the connector's release now that no ciphertext path is
        approved anywhere.
        """

        self.configure_cloudflare_revision()
        path = self.root / TRANSITION.CLOUDFLARE_RELEASE_KUSTOMIZATION
        with path.open("a", encoding="utf-8", newline="\n") as output:
            output.write("  - tunnel-token.yaml\n")
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)


    def test_active_site_is_independent_of_suspended_platform_services(self):
        self.activate_site("naranjo-online")
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(plan.naranjo_online, "active")
        self.assertTrue(plan.platform_suspended)
        self.assertTrue(plan.any_website_active)
        self.assertTrue(plan.any_workload_active)

    def test_direct_sites_have_no_platform_services_prerequisite(self):
        self.activate_both_sites()
        plan = TRANSITION.classify(self.root)
        self.assertEqual(plan.mode, "transition")
        self.assertEqual(
            (plan.naranjo_online, plan.lidersea_com, plan.obsidian),
            ("active", "active", "active"),
        )
        self.assertEqual(plan.cloudflare_public, "initial")
        self.assertTrue(plan.platform_suspended)
        self.assertTrue(plan.any_workload_active)

    def test_any_aggregate_reconciliation_manifest_is_rejected(self):
        aggregate = self.root / "kubernetes/reconciliation/admission.yaml"
        aggregate.parent.mkdir(parents=True)
        aggregate.write_text("kind: Kustomization\n", encoding="utf-8")
        with self.assertRaises(TRANSITION.STATE.CanonicalYamlError):
            TRANSITION.classify(self.root)

    def test_cli_failure_is_generic_and_does_not_disclose_paths(self):
        self.replace_once(
            SITE_FILES["naranjo-online"],
            "    deploymentReady: true\n",
            "    deploymentReady: true\n    unreviewed: true\n",
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = TRANSITION.main(
                ["--root", str(self.root), "select-mode"]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "ERROR release transition state is unavailable or unsafe\n",
        )
        self.assertNotIn(str(self.root), stderr.getvalue())

    def test_plan_requires_the_selected_mode_and_has_fixed_shape(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = TRANSITION.main(
                ["--root", str(self.root), "plan", "--expect-mode", "transition"]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "mode=transition",
                "naranjo-online=staged",
                "lidersea-com=staged",
                "obsidian=staged",
                "cloudflare-public=initial",
                "platform-services-suspended=true",
                "any-website-active=true",
                "any-workload-active=true",
            ],
        )


if __name__ == "__main__":
    unittest.main()
