"""The public handoff procedure retains its current-state and authority order."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs/runbooks/application-source-transition.md"


class ApplicationSourceTransitionRunbookTests(unittest.TestCase):
    def test_census_and_quarantine_order_stays_fail_closed(self):
        text = RUNBOOK.read_text()
        required = (
            "collection resource versions are\nsnapshot markers and need not be equal",
            "including each object's resource version and closed\nowner references",
            "same captured CronJob UID and complete body",
            "an empty selector-account census\nand no selector Job or Pod lineage",
            "they do not prove that no transient\nevent occurred between them",
            "same RoleBinding UID and current object with an empty subject list",
            "complete two-round current-state barrier after this quarantine",
            "denies `patch` on the exact GitRepository",
            "whole-spec,\nwhole-metadata, UID and current-resource-version compare-and-swap",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, text)
        self.assertNotIn("identical\ncorresponding resource versions", text)


if __name__ == "__main__":
    unittest.main()
