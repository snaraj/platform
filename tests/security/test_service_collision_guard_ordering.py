#!/usr/bin/env python3
"""Pin the runtime installer's pre-mutation service-collision gate, textually.

The runtime installer must probe for pre-existing containerd.service and
kubelet.service state (activation, enablement, unit file or drop-in) BEFORE
it mutates the host, and must refuse with its documented message when it
finds any: a fresh host is the only sanctioned runtime-install target.

These are textual pins in the style of test_shell_script_modes.py, not
functional fake-injection probes: the collision gate sits inline in
install-kubernetes.sh's main() behind the root, exact-confirmation, and
payload-SHA gates, so no test harness can execute the whole script without
staging a full signed payload as root. The sibling battery
test_kubelet_partial_init_state_matrix.py drives the gate functionally
anyway — it executes the gate's own extracted text under a fake-systemctl
fixture set (issue #49). These pins hold the placement half of the reviewed
contract: which probes exist, what they refuse, and what must come before
what — not one exact control-flow shape — so a restructuring that preserves
the contract keeps passing while losing a probe, a refusal, or the
pre-mutation placement fails.
"""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"
# The gate must inspect exactly the two services the installer is about to
# create; the loop header is load-bearing because dropping either name
# silently halves the collision surface.
COLLISION_LOOP = "for name in containerd.service kubelet.service; do"
# First mutation marker: everything at or after this point may change the
# host, so every collision probe must appear before it.
TRANSACTION_START = "transaction_started='yes'"


class RuntimeInstallerCollisionGateTests(unittest.TestCase):
    """The runtime installer refuses pre-existing service state, pre-mutation."""

    @classmethod
    def setUpClass(cls):
        cls.script = INSTALLER.read_text(encoding="utf-8")

    def gate_region(self):
        """Return the text from the collision loop to the first mutation.

        Scoping the probe assertions to this region proves the probes belong
        to the collision gate itself, not to some later post-install check
        that would run only after the host was already mutated.
        """

        start = self.script.index(COLLISION_LOOP)
        end = self.script.index(TRANSACTION_START)
        self.assertLess(start, end, "collision loop must precede the transaction")
        return self.script[start:end]

    def test_gate_probes_every_service_state_and_tolerates_none(self):
        # Activation, enablement, and any unit file or drop-in (what
        # `systemctl cat` renders) each refuse; no state is waved through.
        region = self.gate_region()
        for fragment in (
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
            'systemctl cat "${name}" >/dev/null 2>&1; then',
            'die "refusing to replace or alter existing systemd service state: ${name}"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, region)
        for tolerance in ("continue", "DropInPaths", "FragmentPath"):
            with self.subTest(tolerance=tolerance):
                self.assertNotIn(tolerance, region)

    def test_gate_is_ordered_before_every_service_mutation(self):
        marker = self.script.index("phase='pre-mutation-collision-validation'")
        loop = self.script.index(COLLISION_LOOP)
        transaction = self.script.index(TRANSACTION_START)
        first_service_mutation = self.script.index(
            "systemctl enable --now containerd.service"
        )
        self.assertLess(marker, loop)
        self.assertLess(loop, transaction)
        self.assertLess(transaction, first_service_mutation)


if __name__ == "__main__":
    unittest.main()
