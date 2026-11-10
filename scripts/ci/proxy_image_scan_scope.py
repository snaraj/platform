#!/usr/bin/env python3
"""Print ``scan`` or ``skip``: does BASE...HEAD change the proxy image scan's subject?

Usage: python3 -I -B scripts/ci/proxy_image_scan_scope.py <base-sha> <head-sha>

The obsync TLS proxy image is a fixed upstream artifact pinned by digest.
Scanning it on every change turned unrelated pull requests red whenever a CVE
was published against the unchanged pin. Pull-request and main CI therefore
scan it only when the range (from its merge base) touches a file that defines
the image or the scan; ``scheduled-security.yml`` scans main unconditionally.
An all-zero base (no previous commit to compare) answers ``scan``. A malformed
argument or a Git failure exits 1, which fails the step: an unknown range is
never a reason to skip.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Every input that decides which image is scanned or how. A new file that
# defines the image belongs here, in the same change.
TRIGGER_FILES = frozenset({
    "versions.env",  # OBSYNC_TLS_PROXY_IMAGE and the Trivy version
    "policies/conftest/obsync_tls_proxy.rego",  # admits exactly that image
    "scripts/ci/scan-proxy-image.sh",  # the scan and its policy
    "scripts/ci/proxy_image_scan_scope.py",  # this decision
    "scripts/ci/install-tools.sh",  # installs the pinned Trivy
    ".github/workflows/pull-request.yml",  # runs the decision and the scan
    ".github/workflows/scheduled-security.yml",  # the unconditional scan
    # Trivy reads these from the working directory when present.
    ".trivyignore", ".trivyignore.yaml", "trivy.yaml",
})
TRIGGER_PREFIXES = ("kubernetes/platform/obsync-tls-proxy/",)


def needs_scan(paths):
    """True when any changed path defines the image or the scan."""
    return any(path in TRIGGER_FILES or path.startswith(TRIGGER_PREFIXES) for path in paths)


def git(*argv):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.run(["git", *argv], capture_output=True, check=True, timeout=60,
                          env=environment).stdout.decode("utf-8")


def scope(base, head):
    if OID.fullmatch(base) is None or OID.fullmatch(head) is None:
        raise ValueError("base and head must be exact commit ids")
    if set(base) == {"0"}:
        return "scan"
    merge_base = git("merge-base", base, head).strip()
    changed = git("diff", "--name-only", "-z", "--no-renames", merge_base, head).split("\0")
    return "scan" if needs_scan(path for path in changed if path) else "skip"


def main(argv):
    try:
        if len(argv) != 3:
            raise ValueError("usage: proxy_image_scan_scope.py <base-sha> <head-sha>")
        print(scope(argv[1], argv[2]))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"proxy image scan scope: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
