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

The gate has two layers. systemctl refuses an active, enabled or
fragment-backed unit. A filesystem probe refuses any unit-specific drop-in
directory in the system unit search path, because manager-backed systemd
reports a unit with no fragment as not found and ``systemctl cat`` therefore
never sees an orphan override; the probe also refuses when a directory cannot
be read or searched, since absence is then unproven.

The gate sits behind root/exact-confirmation/payload gates, so the whole
script cannot be executed by a test harness (see
test_service_collision_guard_ordering.py, which pins the same contract
textually). This battery gets functional coverage anyway by executing the
gate's OWN text: the region is sliced verbatim out of the shipped script
between load-bearing markers — never re-typed here — prefixed only with a
stub ``die`` and the script's ``unit_root`` seam, which points the
filesystem probe at a real temporary directory tree instead of the host
root, and run under the script's own ``set -euo pipefail`` discipline. If a
restructuring moves the markers, the slice fails loudly instead of silently
testing stale text.

The fake-systemctl fixture makes the run hermetic: a ``systemctl`` shim
earlier on PATH replays one pinned unit state per scenario and logs every
invocation, so no live systemd, host, or network is ever consulted. The shim
models manager-backed exit codes. ``is-active`` succeeds ONLY for an active
(or reloading) unit: ``inactive``, ``failed`` and ``activating``/auto-restart
all exit non-zero, which is why the enablement and unit-file probes are
load-bearing for partial-init states. ``cat`` succeeds only when a fragment
exists: in systemd v255, service_load requires a fragment and
unit_load_fragment_and_dropin returns ENOENT before loading drop-ins, so a
drop-in-only unit is not found and verb_cat fails.
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
# Permission-denial rows need a caller that DAC can deny; root bypasses it.
UNPRIVILEGED = os.name == "posix" and os.geteuid() != 0

SERVICES = ("containerd.service", "kubelet.service")
# Every system unit search directory systemd.unit(5) lists for the system
# manager on an Ubuntu host with merged /usr. Each must be probed for
# <unit>.d; the type-wide service.d/ directories are deliberately not.
SEARCH_DIRECTORIES = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
)

# Refusals exit through the stub ``die`` below with this distinctive code,
# so a scenario's outcome is never confused with an unmodeled-command trip
# (97 from the shim) or an incidental bash failure.
DIE_STATUS = 70
STUB_PREAMBLE = """set -euo pipefail
die() { printf 'DIE %s\\n' "$1" >&2; exit 70; }
unit_root="${FAKE_UNIT_ROOT}"
"""
DROPIN_REFUSAL = "refusing to install beneath an existing drop-in directory: "
UNPROVEN_REFUSAL = "cannot establish drop-in absence for "

# --- The fake-systemctl fixture. -------------------------------------------
# One shim, one pinned unit state per scenario: each unit's state is an
# ``ActiveState|UnitFileState|FragmentPath`` tuple in the environment, and
# every invocation is appended to FAKE_SYSTEMCTL_LOG so the battery can
# attribute a refusal to the exact probe that caught it. Drop-ins are not
# part of the tuple because manager-backed systemctl never reports them for
# a unit without a fragment; they live in the real temporary tree instead.
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
  IFS='|' read -r active_state unit_file_state fragment_path <<<"${state}"
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
    # Manager-backed systemd loads a service only with a fragment; without
    # one the unit is not found and cat fails, whatever drop-ins exist.
    if [[ -n "${fragment_path}" ]]; then
      printf '# %s\\n' "${fragment_path}"
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


def unit_state(active="inactive", unit_file="absent", fragment=""):
    """Encode one unit's pinned systemd state for the shim."""

    return "|".join((active, unit_file, fragment))


# A host with no containerd/kubelet state at all: every kubelet-focused
# scenario pins containerd to this so the loop's first iteration falls
# through and the kubelet leg is exercised in isolation.
UNIT_ABSENT = unit_state()


def build_clean_host(root):
    """Lay out a clean merged-/usr unit tree under ``root``.

    The usual search directories exist and the control/attached ones do not,
    so both the enumerate and the walk-up legs run. Everything that must NOT
    refuse is present: the type-wide service.d/ policy (as the host hardening
    may ship it), drop-ins for other units, and a lookalike name.
    """

    for directory in (
        "etc/systemd/system",
        "run/systemd/system",
        "run/systemd/transient",
        "run/systemd/generator",
        "run/systemd/generator.early",
        "run/systemd/generator.late",
        "usr/lib/systemd/system",
        "usr/local/lib/systemd/system",
    ):
        (root / directory).mkdir(parents=True)
    (root / "lib").symlink_to("usr/lib")
    for dropin in (
        "etc/systemd/system/service.d/10-policy.conf",
        "usr/lib/systemd/system/service.d/10-timeout.conf",
        "etc/systemd/system/cloudflared.service.d/70-platform-sandbox.conf",
        "etc/systemd/system/ssh.socket.d/zzz-platform-listen.conf",
        "run/systemd/system/kubelet.slice.d/50-other.conf",
    ):
        path = root / dropin
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[Unit]\n", encoding="utf-8")


def add_orphan_dropin(root, directory, service, empty=False):
    """Create ``<directory>/<service>.d`` (with one override unless empty)."""

    if directory.startswith("/lib/"):
        # Exercise /lib on its own, as on a host without merged /usr, so the
        # refusal names that directory rather than its /usr/lib alias.
        (root / "lib").unlink()
    dropin = root / directory.lstrip("/") / (service + ".d")
    dropin.mkdir(parents=True)
    if not empty:
        (dropin / "50-foreign.conf").write_text("[Service]\n", encoding="utf-8")
    return dropin


def unlock(path):
    """Restore owner access below ``path`` so cleanup can remove the tree."""

    if path.is_symlink() or not path.is_dir():
        return
    path.chmod(0o700)
    for child in path.iterdir():
        unlock(child)


def slice_region(text, start_marker, end_marker):
    """Cut the gate's shipped text between markers; missing markers raise."""

    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    return text[start:end]


@unittest.skipUnless(os.name == "posix", "the harness drives bash with a PATH shim")
@unittest.skipUnless(BASH, "bash is required to execute the extracted gate")
class FakeSystemctlHarness(unittest.TestCase):
    """Shared machinery: build the shim and tree, run the extracted gate."""

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

    def run_gate(self, region, kubelet, containerd=UNIT_ABSENT, prepare=None):
        """Execute the extracted gate under the fake-systemctl fixture.

        ``prepare`` receives the clean host tree's root and may add state to
        it before the run. Returns ``(completed, log_lines)`` where
        ``log_lines`` is every shim invocation in order.
        """

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            shim = fake_bin / "systemctl"
            shim.write_text(FAKE_SYSTEMCTL, encoding="utf-8")
            shim.chmod(0o700)
            log_path = Path(directory) / "invocations.log"
            log_path.touch()
            root = Path(directory) / "root"
            root.mkdir()
            build_clean_host(root)
            if prepare is not None:
                prepare(root)
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                    "FAKE_SYSTEMCTL_LOG": str(log_path),
                    "FAKE_KUBELET_STATE": kubelet,
                    "FAKE_CONTAINERD_STATE": containerd,
                    "FAKE_UNIT_ROOT": str(root),
                }
            )
            try:
                completed = subprocess.run(
                    [self.bash, "-c", STUB_PREAMBLE + region, "gate"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=environment,
                )
            finally:
                unlock(root)
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
        # Bind the slice to what it must be: all three probe families, the
        # drop-in probe over every search directory, the documented
        # refusals, and none of the mutation machinery that follows the
        # gate — so a marker drift can never leave this battery exercising
        # the wrong text.
        for fragment in (
            'systemctl is-active --quiet "${name}" 2>/dev/null',
            'systemctl is-enabled --quiet "${name}" 2>/dev/null',
            'systemctl cat "${name}" >/dev/null 2>&1; then',
            "refusing to replace or alter existing systemd service state",
            DROPIN_REFUSAL,
            UNPROVEN_REFUSAL,
            '"${unit_root}',
        ) + SEARCH_DIRECTORIES:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.region)
        for mutation in (
            "transaction_started='yes'",
            "systemctl daemon-reload",
            "systemctl enable",
            "exclusive_install",
            "unit_root=",
        ):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, self.region)

    def test_clean_host_passes_and_probes_both_services_in_order(self):
        # The one sanctioned runtime-install target: no containerd/kubelet
        # state anywhere, while type-wide service.d/ policy, other units'
        # drop-ins and absent control/attached directories are all present
        # in the tree. The gate must complete AND must have consulted every
        # systemctl probe for both services, in unit order.
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

    def test_dropin_only_unit_passes_systemctl_and_is_refused_on_disk(self):
        # The review counterexample: no fragment, inactive, not enabled, one
        # override in /etc. All three systemctl probes fail for it, so the
        # refusal must come from the filesystem probe.
        for service in SERVICES:
            with self.subTest(service=service):
                completed, log_lines = self.run_gate(
                    self.region,
                    kubelet=UNIT_ABSENT,
                    prepare=lambda root, service=service: add_orphan_dropin(
                        root, "/etc/systemd/system", service
                    ),
                )
                self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
                self.assertIn(
                    DROPIN_REFUSAL + "/etc/systemd/system/" + service + ".d",
                    completed.stderr,
                )
                self.assertEqual(log_lines[-1], "systemctl cat " + service)

    def test_orphan_dropin_in_every_search_directory_refuses(self):
        for service in SERVICES:
            for directory in SEARCH_DIRECTORIES:
                with self.subTest(service=service, directory=directory):
                    completed, _ = self.run_gate(
                        self.region,
                        kubelet=UNIT_ABSENT,
                        prepare=lambda root, d=directory, s=service: add_orphan_dropin(
                            root, d, s
                        ),
                    )
                    self.assertEqual(
                        completed.returncode, DIE_STATUS, completed.stderr
                    )
                    self.assertIn(
                        DROPIN_REFUSAL + directory + "/" + service + ".d",
                        completed.stderr,
                    )

    def test_empty_dropin_directory_refuses(self):
        # Decision: any <unit>.d entry refuses, even an empty directory, so
        # the gate never has to read an override's contents.
        completed, _ = self.run_gate(
            self.region,
            kubelet=UNIT_ABSENT,
            prepare=lambda root: add_orphan_dropin(
                root, "/run/systemd/system.control", "kubelet.service", empty=True
            ),
        )
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn(
            DROPIN_REFUSAL + "/run/systemd/system.control/kubelet.service.d",
            completed.stderr,
        )

    @unittest.skipUnless(UNPRIVILEGED, "root bypasses the permission denial")
    def test_unreadable_dropin_directory_refuses(self):
        def prepare(root):
            add_orphan_dropin(root, "/etc/systemd/system", "kubelet.service").chmod(0)

        completed, _ = self.run_gate(self.region, kubelet=UNIT_ABSENT, prepare=prepare)
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn(
            DROPIN_REFUSAL + "/etc/systemd/system/kubelet.service.d",
            completed.stderr,
        )

    @unittest.skipUnless(UNPRIVILEGED, "root bypasses the permission denial")
    def test_unreadable_or_unsearchable_search_directory_refuses(self):
        # A search directory that cannot be listed (0300) or searched (0000)
        # leaves absence unproven; the second also hides a real orphan from
        # a plain existence test.
        for mode in (0o300, 0o000):
            with self.subTest(mode=oct(mode)):
                def prepare(root, mode=mode):
                    add_orphan_dropin(root, "/etc/systemd/system", "kubelet.service")
                    (root / "etc/systemd/system").chmod(mode)

                completed, _ = self.run_gate(
                    self.region, kubelet=UNIT_ABSENT, prepare=prepare
                )
                self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
                self.assertIn(
                    UNPROVEN_REFUSAL + "containerd.service in /etc/systemd/system",
                    completed.stderr,
                )

    @unittest.skipUnless(UNPRIVILEGED, "root bypasses the permission denial")
    def test_unsearchable_ancestor_of_a_missing_search_directory_refuses(self):
        # /run/systemd/system.control is absent, but its parent cannot be
        # searched, so the absence cannot be told from a denial.
        completed, _ = self.run_gate(
            self.region,
            kubelet=UNIT_ABSENT,
            prepare=lambda root: (root / "run/systemd").chmod(0o600),
        )
        self.assertEqual(completed.returncode, DIE_STATUS, completed.stderr)
        self.assertIn(
            UNPROVEN_REFUSAL + "containerd.service in /run/systemd/system.control",
            completed.stderr,
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
