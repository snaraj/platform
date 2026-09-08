import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Repository-path references inside runbooks and assurance docs must exist:
# an instruction that cannot be executed as written is documentation rot
# (Phase E case E7). Paths are matched inside backticks to stay precise.
DOC_ROOTS = ("docs/runbooks", "docs/assurance")
PATH_RE = re.compile(
    r"`((?:scripts|bootstrap|policies|kubernetes|tests|docs|infrastructure)"
    r"/[A-Za-z0-9._/-]+)`"
)
# Illustrative names that deliberately do not exist as tracked files.
PLACEHOLDERS = {
    "bootstrap/pi/decisions.env.local",  # ignored-by-design local input
    "bootstrap/pi/cni-manifest.local.yaml",
    "bootstrap/pi/encryption-config.yaml.local",
    "bootstrap/pi/images.lock.local",
    "bootstrap/pi/kubeadm-config.yaml.local",
    "bootstrap/pi/protected-services.env.local",
    "docs/assurance/evidence-ledger.jsonl",  # exists, listed for clarity
    "scripts/__pycache__",  # generated artifact the macOS runbook warns about
}


def referenced_paths():
    for root in DOC_ROOTS:
        for document in sorted((REPO_ROOT / root).rglob("*.md")):
            text = document.read_text(encoding="utf-8")
            for match in PATH_RE.finditer(text):
                yield document.relative_to(REPO_ROOT), match.group(1)


class RunbookReferenceTests(unittest.TestCase):
    def test_every_referenced_repository_path_exists(self):
        missing = []
        for document, reference in referenced_paths():
            candidate = reference.rstrip("/")
            if candidate in PLACEHOLDERS or candidate.endswith(".local"):
                continue
            target = REPO_ROOT / candidate
            if not target.exists():
                missing.append(f"{document}: `{candidate}`")
        self.assertEqual(
            missing,
            [],
            "documented paths that cannot be executed as written:\n"
            + "\n".join(missing),
        )

    def test_reference_scan_actually_sees_documents(self):
        references = list(referenced_paths())
        self.assertGreater(
            len(references),
            10,
            "the reference scan found suspiciously few paths; "
            "pattern or doc roots may have rotted",
        )




class OperatorArtifactTests(unittest.TestCase):
    """A runbook that ships an artifact must ship the one it was reviewed with.

    The obsync application-sync procedure carries an applyable Kustomization
    under `docs/runbooks/artifacts/`, and the allow fixture that proves it
    satisfies this repository's own Conftest policy is a COPY of it. Two files
    with the same bytes and no check between them drift the first time one is
    edited — and the review that produced this artifact found exactly that class
    of defect, a runbook whose YAML the head's own policy rejected.
    """

    ARTIFACT = REPO_ROOT / "docs/runbooks/artifacts/obsync-reconciler.yaml"
    FIXTURE = REPO_ROOT / "tests/kubernetes/fixtures/allow/obsync-reconciler-artifact.yaml"

    def test_the_reviewed_artifact_and_its_policy_fixture_are_identical(self):
        self.assertTrue(self.ARTIFACT.is_file(), self.ARTIFACT)
        self.assertTrue(self.FIXTURE.is_file(), self.FIXTURE)
        self.assertEqual(
            self.ARTIFACT.read_bytes(),
            self.FIXTURE.read_bytes(),
            "the operator artifact and the fixture proving it passes policy "
            "must be the same bytes",
        )

    def test_the_source_path_patch_tests_before_it_replaces(self):
        """A blind replace would overwrite whatever the source currently says."""

        patch = json.loads(
            (REPO_ROOT / "docs/runbooks/artifacts/obsync-source-path.patch.json")
            .read_text(encoding="utf-8")
        )
        operations = [entry["op"] for entry in patch]
        self.assertEqual(operations[-1], "replace")
        self.assertNotIn("replace", operations[:-1])
        tested = {entry["path"] for entry in patch if entry["op"] == "test"}
        for required in ("/metadata/uid", "/metadata/resourceVersion",
                         "/spec/sparseCheckout"):
            self.assertIn(required, tested)
        replacement = patch[-1]["value"]
        self.assertEqual(len(replacement), len(set(replacement)))
        self.assertIn("kubernetes/websites/obsync", replacement)


if __name__ == "__main__":
    unittest.main()
