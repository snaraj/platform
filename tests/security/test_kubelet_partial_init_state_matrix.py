#!/usr/bin/env python3
"""Hermetic kubelet partial-init state matrix for the runtime collision gate.

Issue #49 item 2: a partial control-plane init leaves kubelet.service in
states the happy-path fixtures never exercised — stopped (``inactive`` with
the unit still installed and enabled) or crash-looping (``activating`` with
SubState ``auto-restart``, because systemd keeps restarting a kubelet whose
control plane never came up). The recovery-path gate that must hold against
those states is the runtime installer's pre-mutation collision gate in
bootstrap/pi/install-kubernetes.sh (``for name in containerd.service
kubelet.service``), which must refuse to reinstall over ANY pre-existing
service state.

The gate sits behind root/exact-confirmation/payload gates, so the whole
script cannot be executed by a test harness (see
test_service_collision_guard_ordering.py, which pins the same contract
textually). This battery gets functional coverage anyway by executing the
gate's OWN text: the region is sliced verbatim out of the shipped script
between load-bearing markers — never re-typed here — prefixed only with a
stub ``die`` definition, and run under the script's own ``set -euo
pipefail`` discipline. If a restructuring moves the markers, the slice fails
loudly instead of silently testing stale text.

The fake-systemctl fixture set makes the run hermetic: a ``systemctl``
shim earlier on PATH replays one pinned host state per scenario and logs
every invocation, so no live systemd, host, or network is ever consulted.
The shim models the real exit-code semantics the gate depends on —
verified against systemctl(1) — most importantly that ``is-active``
succeeds ONLY for an active (or reloading) unit: ``inactive``, ``failed``,
and ``activating``/auto-restart all exit non-zero, which is exactly why
the gate's enablement and unit-file probes are load-bearing for partial-init
states and an activation probe alone would wave them through.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "bootstrap" / "pi" / "install-kubernetes.sh"

# Slice markers. COLLISION_LOOP matches the textual pin in
# test_service_collision_guard_ordering.py; the region ends at the loop's
# own two-space ``done``.
COLLISION_LOOP = "for name in containerd.service kubelet.service; do"
COLLISION_END = "\n  done\n"

BASH = shutil.which("bash")

# Refusals exit through the stub ``die`` below with this distinctive code,
# so a scenario's outcome is never confused with an unmodeled-command trip
# (97 from the shims) or an incidental bash failure.
DIE_STATUS = 70
STUB_PREAMBLE = """set -euo pipefail
die() { printf 'DIE %s\\n' "$1" >&2; exit 70; }
"""

# --- The fake-systemctl fixture set. -------------------------------------
# One shim, one pinned host state per scenario: each unit's state is a
# ``ActiveState|UnitFileState|FragmentPath|DropInPaths`` tuple in the
# environment, and every invocation is appended to FAKE_SYSTEMCTL_LOG so
# the battery can attribute a refusal to the exact probe that caught it.
# Unmodeled commands and units exit 97 loudly: the harness must never lean
# on behavior the fixture does not deliberately replay.
FAKE_SYSTEMCTL = """#!/usr/bin/env bash
set -u
printf 'systemctl %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"
unmodeled() { printf 'systemctl-unmodeled %s\\n' "$*" >>"${FAKE_SYSTEMCTL_LOG}"; exit 97; }
load_state() {
  case "$1" in
    kubelet.service) state="${FAKE_KUBELET_STATE}" ;;
    containerd.service) state="${FAKE_CONTAINERD_STATE}" ;;
    *) unmodeled "$@" ;;
  esac
  IFS='|' read -r active_state unit_file_state fragment_path dropin_paths <<<"${state}"
}
case "${1:-}" in
  is-active)
    [[ "${2:-}" == --quiet && -n "${3:-}" ]] || unmodeled "$@"
    load_state "$3"
    # systemctl(1): is-active succeeds only when the unit IS active (or
    # reloading). inactive, failed, and activating/auto-restart all exit
    # 3 — the crash-looping partial-init kubelet is invisible to this
    # probe, which is why the gate cannot rely on it alone.
    [[ "${active_state}" == active ]] && exit 0
    exit 3
    ;;
  is-enabled)
    [[ "${2:-}" == --quiet && -n "${3:-}" ]] || unmodeled "$@"
    load_state "$3"
    # enabled exits 0; disabled exits 1; a unit with no unit file at all
    # fails with a lookup error. The gate branches only on success.
    [[ "${unit_file_state}" == enabled ]] && exit 0
    exit 1
    ;;
  cat)
    [[ -n "${2:-}" ]] || unmodeled "$@"
    load_state "$2"
    # cat renders whatever unit files exist — fragment and/or drop-ins —
    # and fails only when there are none. A drop-in without a fragment
    # therefore SUCCEEDS, so the gate refuses it like any other unit file.
    if [[ -n "${fragment_path}" || -n "${dropin_paths}" ]]; then
      printf '# %s\\n' "${fragment_path:-${dropin_paths}}"
      exit 0
    fi
    printf 'No files found for %s.\\n' "$2" >&2
    exit 1
    ;;
  *) unmodeled "$@" ;;
esac
"""

# Real unit-file locations as the installer creates them; used verbatim in
# fixtures so unit-file refusals exercise the true post-partial-init
# shape rather than a placeholder.
KUBELET_FRAGMENT = "/etc/systemd/system/kubelet.service"
CONTAINERD_FRAGMENT = "/etc/systemd/system/containerd.service"


def unit_state(active="inactive", unit_file="absent", fragment="", dropins=""):
    """Encode one unit's pinned systemd state for the shim."""

    return "|".join((active, unit_file, fragment, dropins))


# A host with no containerd/kubelet state at all: every kubelet-focused
# scenario pins containerd to this so the loop's first iteration falls
# through and the kubelet leg is exercised in isolation.
UNIT_ABSENT = unit_state()


def slice_region(text, start_marker, end_marker):
    """Cut the gate's shipped text between markers; missing markers raise."""

    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    return text[start:end]


@unittest.skipUnless(os.name == "posix", "the harness drives bash with a PATH shim")
@unittest.skipUnless(BASH, "bash is required to execute the extracted gate")
class FakeSystemctlHarness(unittest.TestCase):
    """Shared machinery: build the shim, run the extracted gate region."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # Resolve the Optional interpreter once, before any argv exists:
        # the class-level skip already excludes bash-less hosts, and this
        # fail-closed floor keeps a None out of subprocess argv if that
        # guard is ever lost. Subclasses extend setUpClass and must call
        # super().
        cls.bash = required_tool(
            BASH, "bash not found - the partial-init matrix cannot run"
        )

    def run_gate(self, region, kubelet, containerd=UNIT_ABSENT):
        """Execute the extracted gate under the fake-systemctl fixture.

        Returns ``(completed, log_lines)`` where ``log_lines`` is every
        shim invocation in order.
        """

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            shim = fake_bin / "systemctl"
            shim.write_text(FAKE_SYSTEMCTL, encoding="utf-8")
            shim.chmod(0o700)
            log_path = Path(directory) / "invocations.log"
            log_path.touch()
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                    "FAKE_SYSTEMCTL_LOG": str(log_path),
                    "FAKE_KUBELET_STATE": kubelet,
                    "FAKE_CONTAINERD_STATE": containerd,
                }
            )
            completed = subprocess.run(
                [self.bash, "-c", STUB_PREAMBLE + region, "gate"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            log_lines = log_path.read_text(encoding="utf-8").splitlines()
        self.assertNotEqual(
            completed.returncode,
            97,
            "the gate reached a command/unit the fixture does not model: %r"
            % (log_lines,),
        )
        return completed, log_lines


class RuntimeInstallerCollisionGateMatrixTests(FakeSystemctlHarness):
    """Drive the shipped collision gate across the partial-init state matrix."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.region = slice_region(
            INSTALLER.read_text(encoding="utf-8"), COLLISION_LOOP, COLLISION_END
        )

    def test_extracted_region_is_the_pre_mutation_collision_gate(self):
        # Bind the slice to what it must be: all three probe families and
        # the documented refusal, and none of the mutation machinery that
        # follows the gate — so a marker drift can never leave this battery
        # exercising the wrong text.
        for fragment in (
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
            'systemctl cat "${name}" >/dev/null 2>&1; then',
            "refusing to replace or alter existing systemd service state",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.region)
        for mutation in (
            "transaction_started='yes'",
            "systemctl daemon-reload",
            "systemctl enable",
            "exclusive_install",
        ):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, self.region)

    def test_clean_host_passes_and_probes_both_services_in_order(self):
        # The one sanctioned runtime-install target: no containerd/kubelet
        # state anywhere. The gate must complete AND must have consulted
        # every probe for both services, in unit order — the functional
        # twin of the textual loop-header pin.
        completed, log_lines = self.run_gate(self.region, kubelet=UNIT_ABSENT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            log_lines,
            [
                "systemctl is-active --quiet containerd.service",
                "systemctl is-enabled --quiet containerd.service",
                "systemctl cat containerd.service",
                "systemctl is-active --quiet kubelet.service",
                "systemctl is-enabled --quiet kubelet.service",
                "systemctl cat kubelet.service",
            ],
        )

    def test_dropin_only_kubelet_refuses_via_the_unit_file_probe(self):
        # A kubelet drop-in with no fragment, no activation and no
        # enablement is still foreign service state: `systemctl cat`
        # renders it, so the gate refuses rather than installing beneath it.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                dropins="/etc/systemd/system/kubelet.service.d/50-foreign.conf"
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertEqual(
            log_lines[-3:],
            [
                "systemctl is-active --quiet kubelet.service",
                "systemctl is-enabled --quiet kubelet.service",
                "systemctl cat kubelet.service",
            ],
        )

    def assert_refused_for(self, completed, unit):
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn(
            "refusing to replace or alter existing systemd service state: " + unit,
            completed.stderr,
        )

    def test_active_kubelet_refuses_via_the_activation_probe(self):
        # Init got far enough to start kubelet before failing: the very
        # first kubelet probe catches it, and the shell's short-circuit
        # proves it — no enablement probe ever runs.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="active", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl is-enabled --quiet kubelet.service", log_lines)

    def test_inactive_enabled_kubelet_refuses_via_the_enablement_probe(self):
        # Partial-init state 1: kubelet stopped but still installed and
        # enabled. is-active exits 3 for inactive, so the refusal REQUIRES
        # the enablement probe — both invocations in the log prove the
        # activation probe alone would have waved this host through.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="inactive", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertIn("systemctl is-enabled --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl cat kubelet.service", log_lines)

    def test_restarting_kubelet_refuses_via_the_enablement_probe(self):
        # Partial-init state 2: kubelet crash-looping under auto-restart.
        # ActiveState is ``activating`` — NOT active — so is-active exits 3
        # here too; only the enablement probe stands between this host and
        # a reinstall over a unit systemd is about to start again.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertIn("systemctl is-active --quiet kubelet.service", log_lines)
        self.assertIn("systemctl is-enabled --quiet kubelet.service", log_lines)
        self.assertNotIn("systemctl cat kubelet.service", log_lines)

    def test_inactive_disabled_kubelet_unit_refuses_via_the_unit_file_probe(self):
        # An operator who disabled kubelet mid-recovery but left the unit
        # file: activation and enablement probes both miss, so the refusal
        # falls to the cat probe.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="inactive",
                unit_file="disabled",
                fragment=KUBELET_FRAGMENT,
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertEqual(log_lines[-1], "systemctl cat kubelet.service")

    def test_restarting_disabled_kubelet_unit_refuses_via_the_unit_file_probe(self):
        # The crash-loop variant of the same recovery posture: disabled but
        # manually started into auto-restart. Same unit-file refusal.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating",
                unit_file="disabled",
                fragment=KUBELET_FRAGMENT,
            ),
        )
        self.assert_refused_for(completed, "kubelet.service")
        self.assertEqual(log_lines[-1], "systemctl cat kubelet.service")

    def test_full_partial_init_host_refuses_on_containerd_before_kubelet(self):
        # The faithful whole-host state after a partial init: containerd
        # still running and enabled, kubelet crash-looping. The gate must
        # refuse on the loop's FIRST iteration — containerd — before any
        # kubelet probe runs at all.
        completed, log_lines = self.run_gate(
            self.region,
            kubelet=unit_state(
                active="activating", unit_file="enabled", fragment=KUBELET_FRAGMENT
            ),
            containerd=unit_state(
                active="active", unit_file="enabled", fragment=CONTAINERD_FRAGMENT
            ),
        )
        self.assert_refused_for(completed, "containerd.service")
        self.assertEqual(
            log_lines, ["systemctl is-active --quiet containerd.service"]
        )


if __name__ == "__main__":
    unittest.main()
