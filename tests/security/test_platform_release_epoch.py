"""Guard the one terminal-v2 to selector-free v3 release edge."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .support import load_script

ROOT = Path(__file__).resolve().parents[2]
EPOCH = load_script("ci/platform_release_epoch.py")
CONTRACT = load_script("ci/platform_release_contract.py")
SOURCE = "8" * 40
TREE = "9" * 40
TAG_OBJECT = "a" * 40


class PlatformReleaseEpochTests(unittest.TestCase):
    def test_v1_v2_history_and_v3_current_roots_are_closed(self):
        self.assertEqual(EPOCH.identity("v0.1.69")["version"], 1)
        self.assertEqual(EPOCH.identity("v0.1.70")["version"], 2)
        current = EPOCH.identity("v0.1.78")
        self.assertEqual(current["version"], 3)
        self.assertEqual(current["repository"], "snaraj/platform")
        self.assertNotIn("selector_digest", current)
        self.assertNotIn("selector_source", current)
        self.assertEqual(EPOCH.identity("v9.9.9")["version"], 3)

    def test_first_v3_accepts_only_the_verified_terminal_v2(self):
        value = EPOCH.publication(
            "snaraj/platform", EPOCH.REPOSITORY_ID, "v0.1.78",
            EPOCH.TERMINAL_V2_TAG, EPOCH.TERMINAL_V2_SOURCE,
        )
        self.assertEqual(value["version"], 3)
        for base_tag, base_sha in (
            ("v0.1.76", EPOCH.TERMINAL_V2_SOURCE),
            (EPOCH.TERMINAL_V2_TAG, "0" * 40),
        ):
            with self.assertRaises(ValueError):
                EPOCH.publication("snaraj/platform", EPOCH.REPOSITORY_ID,
                                  "v0.1.78", base_tag, base_sha)

    def test_v3_schema_is_closed_and_omits_retired_fields(self):
        folder = ROOT / "bootstrap/flux/release-selector"
        v1 = folder / "platform-release-identity.v1.schema.json"
        self.assertEqual(
            __import__("hashlib").sha256(v1.read_bytes()).hexdigest(),
            "2ed4c4460e0ba7870b357bb7489a40f44f3d3364355ac02f5ca5fc2de22987d7",
        )
        schema = json.loads((folder / "platform-release-identity.v3.schema.json").read_bytes())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["$id"], EPOCH.identity("v0.1.78")["schema"])
        self.assertEqual(schema["properties"]["repository_id"], {"const": EPOCH.REPOSITORY_ID})
        self.assertNotIn("selector", schema["properties"])
        self.assertNotIn("sites", schema["properties"])
        self.assertNotIn("selector", schema["required"])
        self.assertNotIn("sites", schema["required"])

    def test_v3_renderer_has_no_retired_identity_fields(self):
        window = CONTRACT.TransitionWindow(
            base_sha=EPOCH.TERMINAL_V2_SOURCE,
            base_tag=EPOCH.TERMINAL_V2_TAG,
            intent=CONTRACT.Intent(SOURCE, CONTRACT.Version(0, 1, 78)),
            fragment_path="changelog.d/1-selector-retirement.md",
            fragment_sha256="b" * 64,
        )
        with (
            mock.patch.object(CONTRACT, "_exact_commit", return_value=SOURCE),
            mock.patch.object(CONTRACT, "_git", return_value=TREE),
            mock.patch.object(CONTRACT, "discover_transition_window", return_value=window),
        ):
            rendered = json.loads(CONTRACT.render_release_identity(
                ROOT, SOURCE, "v0.1.78",
                expected_base_sha=EPOCH.TERMINAL_V2_SOURCE,
                expected_base_tag=EPOCH.TERMINAL_V2_TAG,
                tag_object_sha=TAG_OBJECT, release_id=1,
                main_run_id=2, main_run_attempt=1,
                platform_run_id=3, platform_run_attempt=1,
                github_repository="snaraj/platform",
                github_repository_id=EPOCH.REPOSITORY_ID,
            ))
        self.assertEqual(rendered["schema"], EPOCH.identity("v0.1.78")["schema"])
        self.assertNotIn("selector", rendered)
        self.assertNotIn("sites", rendered)
        self.assertEqual(rendered["predecessor"], {
            "tag": EPOCH.TERMINAL_V2_TAG,
            "peeled_commit": EPOCH.TERMINAL_V2_SOURCE,
        })

    def test_current_workflow_and_publisher_have_no_selector_build_surface(self):
        workflow = (ROOT / ".github/workflows/platform-release.yml").read_text()
        publisher = (ROOT / "scripts/ci/publish-platform-release.sh").read_text()
        pull_request = (ROOT / ".github/workflows/pull-request.yml").read_text()
        for retired in ("SELECTOR_IMAGE_DIGEST", "SELECTOR_BUILD_SHA"):
            self.assertNotIn(retired, workflow)
            self.assertNotIn(retired, publisher)
        self.assertNotIn("cmd/platform-release-selector/Dockerfile", pull_request)
        self.assertNotIn("validate_selector_rootfs.py", pull_request)

    def test_cli_requires_exact_original_repository_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "repository.json"
            args = ["epoch", "v0.1.78", "--repository", "snaraj/platform",
                    "--repository-id", str(EPOCH.REPOSITORY_ID), "--base-tag",
                    EPOCH.TERMINAL_V2_TAG, "--base-sha", EPOCH.TERMINAL_V2_SOURCE,
                    "--source-sha", SOURCE, "--repository-json", str(record)]
            record.write_text(json.dumps({"full_name": "snaraj/platform", "id": EPOCH.REPOSITORY_ID}))
            with mock.patch("sys.argv", args):
                self.assertEqual(EPOCH.main(), 0)
            record.write_text(json.dumps({"full_name": "snaraj/platform", "id": EPOCH.REPOSITORY_ID + 1}))
            with mock.patch("sys.argv", args):
                self.assertEqual(EPOCH.main(), 1)


if __name__ == "__main__":
    unittest.main()
