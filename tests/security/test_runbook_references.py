import json
import re
import tempfile
import unittest
from pathlib import Path

from .support import load_script

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = load_script("validate_repository.py")

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

    def test_the_shipped_source_path_patch_is_the_reviewed_operation_list(self):
        """The artifact is bound whole, not sampled for properties it has.

        The predecessor asserted a SHAPE — one trailing `replace`, no earlier
        one, three tested paths present — and a shape is not an admission
        boundary. A fourth path appended to the new list and a deleted
        `/spec/ref/branch` test both satisfied every one of those assertions.
        `scripts/validate_repository.py` now holds the reviewed operation list
        and compares the parsed document to it; this reads the same constant
        rather than restating it, so there is one place of truth.
        """

        shipped = json.loads(
            (REPO_ROOT / VALIDATOR.REVIEWED_SOURCE_PATCH_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(shipped, [dict(op) for op in VALIDATOR.REVIEWED_SOURCE_PATCH])
        self.assertEqual(VALIDATOR.reviewed_source_patch_errors(REPO_ROOT), [])

    def test_the_reviewed_operation_list_is_what_the_runbook_claims(self):
        """The runbook's prose is a claim about this list; bind it to the list.

        Section 1 promises that every prior fact is tested before the single
        replace, and that the widening is one path. If the constant ever stops
        meeting that description, the runbook is lying and this fails.
        """

        operations = [dict(op) for op in VALIDATOR.REVIEWED_SOURCE_PATCH]
        self.assertEqual([op["op"] for op in operations[:-1]], ["test"] * 4)
        self.assertEqual(operations[-1]["op"], "replace")
        self.assertEqual(
            [op["path"] for op in operations],
            ["/metadata/uid", "/metadata/resourceVersion", "/spec/ref/branch",
             "/spec/sparseCheckout", "/spec/sparseCheckout"],
        )
        self.assertEqual(operations[2]["value"], "main")
        old_paths, new_paths = operations[3]["value"], operations[-1]["value"]
        self.assertEqual(new_paths[:len(old_paths)], old_paths)
        self.assertEqual(new_paths[len(old_paths):], ["kubernetes/websites/obsync"])
        self.assertEqual(len(new_paths), len(set(new_paths)))

    def test_a_patch_that_is_not_the_reviewed_list_is_refused(self):
        """The two mutants review found, and three of the same shape.

        Each is written into a temporary tree holding only this artifact, so
        the refusal is the closure's and nothing else's.
        """

        reviewed = [dict(op) for op in VALIDATOR.REVIEWED_SOURCE_PATCH]

        def fourth_path():
            mutated = [dict(op) for op in reviewed]
            mutated[-1] = dict(mutated[-1],
                               value=mutated[-1]["value"] + ["kubernetes/websites/fourth"])
            return mutated

        def branch_test_deleted():
            return [op for op in reviewed if op["path"] != "/spec/ref/branch"]

        def reordered_new_list():
            mutated = [dict(op) for op in reviewed]
            mutated[-1] = dict(mutated[-1], value=list(reversed(mutated[-1]["value"])))
            return mutated

        def replace_on_the_branch():
            return [dict(op, op="replace") if op["path"] == "/spec/ref/branch" else op
                    for op in reviewed]

        def remove_appended():
            return reviewed + [{"op": "remove", "path": "/spec/ignore"}]

        cases = (
            ("a fourth sparseCheckout path", fourth_path),
            ("the /spec/ref/branch test deleted", branch_test_deleted),
            ("the new list reordered", reordered_new_list),
            ("a replace on the branch", replace_on_the_branch),
            ("a remove op appended", remove_appended),
        )
        with tempfile.TemporaryDirectory() as directory:
            # Resolved: the validator reads through a no-symlink component
            # chain, and macOS puts temporary directories under /var -> /private/var.
            root = Path(directory).resolve()
            artifact = root / VALIDATOR.REVIEWED_SOURCE_PATCH_PATH
            artifact.parent.mkdir(parents=True)
            # The closure is enforced wherever the runbook that instructs an
            # operator to apply the patch exists, so the fixture tree carries it.
            (root / VALIDATOR.REVIEWED_SOURCE_PATCH_RUNBOOK).write_text(
                "# fixture\n", encoding="utf-8"
            )
            for label, mutate in cases:
                artifact.write_text(json.dumps(mutate(), indent=2) + "\n", encoding="utf-8")
                with self.subTest(mutation=label):
                    self.assertEqual(
                        VALIDATOR.reviewed_source_patch_errors(root),
                        ["reviewed source-path patch is not the reviewed operation list"],
                    )
            # A repeated key would otherwise keep the last value silently.
            artifact.write_text(
                '[{"op": "test", "op": "remove", "path": "/spec/ignore"}]\n',
                encoding="utf-8",
            )
            with self.subTest(mutation="a repeated JSON key"):
                self.assertEqual(
                    VALIDATOR.reviewed_source_patch_errors(root),
                    ["reviewed source-path patch is unreadable"],
                )
            # The control: the reviewed list itself is admitted.
            artifact.write_text(json.dumps(reviewed, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(VALIDATOR.reviewed_source_patch_errors(root), [])
            # And deleting the artifact while the runbook still cites it is not
            # a way out of the closure.
            artifact.unlink()
            self.assertEqual(
                VALIDATOR.reviewed_source_patch_errors(root),
                ["reviewed source-path patch is unreadable"],
            )


if __name__ == "__main__":
    unittest.main()
