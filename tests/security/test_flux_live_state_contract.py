"""Offline Flux generation and retired live-entry-point contracts."""

import os
import re
import sys
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import REPO_ROOT as ROOT, required_tool

BOOTSTRAP = ROOT / "bootstrap/flux/bootstrap.sh"
BASH = shutil.which("bash")
BASH_REQUIRED = "Bash is required for generation checks"


class FluxGenerationContractTests(unittest.TestCase):
    @unittest.skipUnless(BASH, "Bash is required for startup-environment rejection")
    def test_bash_startup_environment_fails_before_target_or_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            startup = Path(directory) / "startup.sh"
            startup.write_text("inherited_hook() { :; }\n", encoding="utf-8")
            environment = {**os.environ, "BASH_ENV": str(startup)}
            result = subprocess.run(
                [required_tool(BASH, BASH_REQUIRED), str(BOOTSTRAP), "--generate"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "FAIL Flux operation made no cluster mutation.\n")


    @unittest.skipUnless(BASH, "Bash is required")
    def test_retired_live_modes_fail_without_private_inputs(self):
        for script, mode in ((BOOTSTRAP, "--apply-controllers"),
                             (BOOTSTRAP, "--apply-sync"),
                             (BOOTSTRAP, "--verify"),
                             (ROOT / "bootstrap/flux/verify.sh", "--verify")):
            with self.subTest(script=script.name, mode=mode):
                result = subprocess.run(
                    [required_tool(BASH, BASH_REQUIRED), str(script), mode],
                    env={"PATH": "/usr/bin:/bin"}, capture_output=True,
                    text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "BLOCKED Flux live modes are retired; no protected file was read and no cluster request was attempted.\n")

    def test_generation_checks_private_binary_copy_before_execution(self):
        source = BOOTSTRAP.read_text(encoding="utf-8")
        copy = source.index('copy_stable_file "${flux_source}" "${flux}" || fail')
        checksum = source.index('[[ "$(sha256sum -- "${flux}"')
        execute = source.index('"${flux}" version --client')
        self.assertLess(copy, checksum)
        self.assertLess(checksum, execute)
        self.assertIn('--components=source-controller,kustomize-controller,helm-controller', source)
        self.assertIn('--network-policy=true --export', source)
        self.assertIn('if count != 1:', source)
        self.assertEqual(source.count('sha256sum -- "${flux}"'), 2)

    def test_generation_replaces_all_three_images_and_rejects_incomplete_export(self):
        source = BOOTSTRAP.read_text(encoding="utf-8")
        program = re.search(r"<<'PY'.*?\n(.*?)\nPY\n", source, re.S).group(1)
        originals = ("ghcr.io/fluxcd/source-controller:v1.9.3",
                     "ghcr.io/fluxcd/kustomize-controller:v1.9.4",
                     "ghcr.io/fluxcd/helm-controller:v1.6.3")
        keys = ("SOURCE_IMAGE", "KUSTOMIZE_IMAGE", "HELM_IMAGE")
        pins = {key: image + "@sha256:" + str(i) * 64
                for i, (key, image) in enumerate(zip(keys, originals), 1)}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "components.yaml"
            for images in (originals, originals[:-1], originals + originals[:1],
                           (originals[0] + "0", *originals[1:])):
                with self.subTest(image_count=len(images)):
                    before = "\n".join("image: " + image for image in images) + "\n"
                    path.write_text(before, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-I", "-c", program],
                        env={**pins, "COMPONENTS_PATH": str(path)},
                        capture_output=True, check=False, timeout=10,
                    )
                    if images == originals:
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(path.read_text(), "\n".join(
                            "image: " + pins[key] for key in keys) + "\n")
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(path.read_text(), before)

    def test_generation_rejects_wrong_publisher_component_digest_and_version(self):
        source = BOOTSTRAP.read_text(encoding="utf-8")
        program = re.search(r"<<'PY'.*?\n(.*?)\nPY\n", source, re.S).group(1)
        images = {key: "ghcr.io/fluxcd/" + component + "-controller:v9.8.7@sha256:" + "a" * 64
                  for key, component in (("SOURCE_IMAGE", "source"),
                                         ("KUSTOMIZE_IMAGE", "kustomize"),
                                         ("HELM_IMAGE", "helm"))}
        before = "\n".join("image: " + pin.split("@")[0] for pin in images.values()) + "\n"
        wrong = (images["SOURCE_IMAGE"].replace("fluxcd/", "other/"),
                 images["HELM_IMAGE"], images["SOURCE_IMAGE"][:-1],
                 images["SOURCE_IMAGE"].replace("v9.8.7", "v9.8.8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "components.yaml"
            for pin in (images["SOURCE_IMAGE"], *wrong):
                with self.subTest(pin=pin):
                    path.write_text(before)
                    result = subprocess.run([sys.executable, "-I", "-B", "-c", program],
                        env={**images, "SOURCE_IMAGE": pin, "COMPONENTS_PATH": str(path)},
                        capture_output=True, check=False, timeout=10)
                    if pin == images["SOURCE_IMAGE"]:
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(path.read_text().count("@sha256:"), 3)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(path.read_text(), before)
