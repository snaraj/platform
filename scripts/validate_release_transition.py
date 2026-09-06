#!/usr/bin/env python3
"""Classify only safe, canonical GitOps release transitions.

This module deliberately builds on ``validate_release_state.py``'s closed YAML
grammar.  It adds the cross-release dependency rules needed by CI without
turning the release-state parser into a general YAML loader.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
CLOUDFLARE_RELEASE_KUSTOMIZATION = Path(
    "kubernetes/platform/cloudflare-public/release/kustomization.yaml"
)
# One public Tunnel per website, never a shared one and never a third. Each
# site root owns exactly one Tunnel whose name is that site's identity tuple,
# and the other site's identity token must not appear anywhere inside it.


def _load_release_state_module():
    """Load the exact sibling parser, never an ambient module of that name."""

    state_path = Path(__file__).resolve().with_name("validate_release_state.py")
    specification = importlib.util.spec_from_file_location(
        "_website_infrastructure_release_state", state_path
    )
    if specification is None or specification.loader is None:
        raise ImportError("release-state parser cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


STATE = _load_release_state_module()


class TransitionPlan(NamedTuple):
    """One fully classified, dependency-safe desired-state transition."""

    mode: str
    naranjo_online: str
    lidersea_com: str
    cloudflare_public: str
    platform_suspended: bool
    naranjo_parent_suspended: bool
    lidersea_parent_suspended: bool

    @property
    def any_website_active(self) -> bool:
        """Keep production controls while a site is live or directly selected.

        The #189 topology has no suspendable aggregate parent: both direct site
        Kustomizations always select their exact website paths. A staged
        HelmRelease therefore still sits inside an active reconciliation and
        keeps the website signature/capacity envelope mandatory.
        """

        return (
            "active" in (self.naranjo_online, self.lidersea_com)
            or not self.naranjo_parent_suspended
            or not self.lidersea_parent_suspended
        )

    @property
    def any_workload_active(self) -> bool:
        return (
            self.any_website_active
            or self.cloudflare_public == "active"
            or not self.platform_suspended
        )


_BLOCK_KIND_KEY = re.compile(r"^(?:kind|\"kind\"|'kind')\s*:")
_BLOCK_SECRET_KIND = re.compile(
    r"^(?:kind|\"kind\"|'kind')\s*:\s*(?:Secret|\"Secret\"|'Secret')"
    r"\s*(?:#.*)?$"
)
_FLOW_SECRET_KIND = re.compile(
    r"(?:^|[,{])\s*(?:kind|\"kind\"|'kind')\s*:\s*"
    r"(?:Secret|\"Secret\"|'Secret')\s*(?:[,}]|$)"
)


def _top_level_yaml_lines(document: str) -> list[str]:
    """Return root-level significant lines without interpreting permissive YAML."""

    significant = [
        line
        for line in document.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not significant:
        return []
    base_indent = min(len(line) - len(line.lstrip(" ")) for line in significant)
    return [
        line[base_indent:]
        for line in significant
        if len(line) - len(line.lstrip(" ")) == base_indent
    ]


def _secret_kind_state(document: str) -> tuple[bool, bool]:
    """Return (is Secret-like, uses one canonical top-level kind spelling)."""

    top_level = _top_level_yaml_lines(document)
    kind_lines = [line for line in top_level if _BLOCK_KIND_KEY.match(line)]
    secret_lines = [line for line in kind_lines if _BLOCK_SECRET_KIND.fullmatch(line)]
    flow_secret = _FLOW_SECRET_KIND.search(document) is not None
    # YAML tags, anchors, aliases, block scalars, collections, and escaped
    # quoted scalars can all resolve to ``Secret`` while hiding that literal
    # from a narrow regex. This repository requires a plain canonical kind, so
    # any such kind value is conservatively Secret-like and rejected unless it
    # is exactly ``kind: Secret``.
    suspicious_kind = False
    for line in document.splitlines():
        match = re.match(
            r"^\s*(?:kind|\"kind\"|'kind')\s*:\s*(.*?)\s*(?:#.*)?$",
            line,
        )
        if match is None:
            continue
        value = match.group(1)
        if re.search(r"(?<![A-Za-z])Secret(?![A-Za-z])", value):
            suspicious_kind = True
        elif value.startswith(("!", "&", "*", "|", ">", "[", "{")):
            suspicious_kind = True
        elif value.startswith(('"', "'")) and "\\" in value:
            suspicious_kind = True
    secret_like = bool(secret_lines or flow_secret or suspicious_kind)
    canonical = (
        secret_like
        and not flow_secret
        and kind_lines == ["kind: Secret"]
    )
    return secret_like, canonical


def contains_secret_document(text: str) -> bool:
    """Recognize canonical and noncanonical root-level Secret declarations."""

    return any(
        _secret_kind_state(document)[0]
        for document in re.split(r"(?m)^---\s*$", text)
    )


def _require_secretless_public_release(root: Path) -> None:
    """Prove the public release inventory carries no Secret of any kind.

    The repository holds no secrets: the connector's Tunnel token is created on
    the cluster by an owner ceremony (AGENTS.md safety invariant 7).  Pinning
    this Kustomization to its exact two resources is what stops a Secret — or a
    file that merely renders one — from being re-listed here.
    """

    text = STATE._read_canonical_text(root / CLOUDFLARE_RELEASE_KUSTOMIZATION)
    significant = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if significant != [
        "apiVersion: kustomize.config.k8s.io/v1beta1",
        "kind: Kustomization",
        "resources:",
        "  - source.yaml",
        "  - release.yaml",
    ]:
        raise STATE.CanonicalYamlError(
            "public release Kustomization is outside the closed resource inventory"
        )


def _website_phase(name: str, root: Path, parent_suspended: bool) -> str:
    """Classify one site while preserving deterministic gate ordering.

    An active HelmRelease requires an active parent. A suspended HelmRelease
    may safely sit below either parent state: that is the required intermediate
    while rollback suspends the inner controller before its parent, and while
    resume reactivates the parent before the inner controller.
    """

    release = STATE.load_helm_release(name, root)
    if not release.suspended and parent_suspended:
        raise STATE.CanonicalYamlError(
            "active website release requires an active parent"
        )

    return "staged" if release.suspended else "active"


def _cloudflare_phase(root: Path, platform_suspended: bool) -> str:
    """Classify the connector while allowing its parent to serve sites first."""

    release = STATE.load_helm_release("cloudflare-public", root)
    # Each website's connector owns its own revision. A half-configured pair is
    # not a safe intermediate — it would mean one Tunnel was staged while the
    # other still carries a sentinel — so it fails closed rather than being
    # classified.
    configured_flags = {
        str(release.values[("connectors", site, "tokenRevision")])
        not in {"not-configured", "UNRESOLVED"}
        for site in STATE.PUBLIC_CONNECTOR_SITES
    }
    if len(configured_flags) != 1:
        raise STATE.CanonicalYamlError(
            "connector token revisions must be uniformly configured"
        )
    configured = configured_flags.pop()
    _require_secretless_public_release(root)

    if release.suspended and not configured:
        return "initial"
    if release.suspended and configured:
        return "staged"
    if not release.suspended and configured and not platform_suspended:
        return "active"
    raise STATE.CanonicalYamlError("cloudflare release state is unsafe")


def classify(root: Path = ROOT) -> TransitionPlan:
    """Return scaffold, transition, or release for one exact safe state."""

    root = root.resolve()
    platform_suspended = STATE.load_parent_suspension("cloudflare-public", root)
    naranjo_parent_suspended = STATE.load_parent_suspension(
        "naranjo-online", root
    )
    lidersea_parent_suspended = STATE.load_parent_suspension(
        "lidersea-com", root
    )
    naranjo_phase = _website_phase(
        "naranjo-online", root, naranjo_parent_suspended
    )
    lidersea_phase = _website_phase(
        "lidersea-com", root, lidersea_parent_suspended
    )
    cloudflare_phase = _cloudflare_phase(root, platform_suspended)

    # The direct website loop is independent of any retired admission-controller
    # premise.

    if (
        naranjo_phase == "staged"
        and lidersea_phase == "staged"
        and cloudflare_phase == "initial"
        and platform_suspended
        and naranjo_parent_suspended
        and lidersea_parent_suspended
    ):
        mode = "scaffold"
    elif (
        naranjo_phase == "active"
        and lidersea_phase == "active"
        and cloudflare_phase == "active"
        and not platform_suspended
    ):
        mode = "release"
    else:
        mode = "transition"

    return TransitionPlan(
        mode,
        naranjo_phase,
        lidersea_phase,
        cloudflare_phase,
        platform_suspended,
        naranjo_parent_suspended,
        lidersea_parent_suspended,
    )


def _print_plan(plan: TransitionPlan) -> None:
    """Emit a fixed, non-executable record for the Bash renderer."""

    print("mode={}".format(plan.mode))
    print("naranjo-online={}".format(plan.naranjo_online))
    print("lidersea-com={}".format(plan.lidersea_com))
    print("cloudflare-public={}".format(plan.cloudflare_public))
    print(
        "platform-services-suspended={}".format(
            "true" if plan.platform_suspended else "false"
        )
    )
    print(
        "any-website-active={}".format(
            "true" if plan.any_website_active else "false"
        )
    )
    print(
        "any-workload-active={}".format(
            "true" if plan.any_workload_active else "false"
        )
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("select-mode")
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument(
        "--expect-mode", required=True, choices=("scaffold", "transition", "release")
    )
    args = parser.parse_args(argv)

    try:
        plan = classify(args.root)
        if args.command == "select-mode":
            print(plan.mode)
        elif plan.mode != args.expect_mode:
            raise STATE.CanonicalYamlError("release mode changed between checks")
        else:
            _print_plan(plan)
    except (STATE.CanonicalYamlError, OSError, RuntimeError, UnicodeError):
        print(
            "ERROR release transition state is unavailable or unsafe",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
