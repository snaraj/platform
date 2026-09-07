#!/usr/bin/env python3
"""Report upstream release drift without changing pins, Git or the cluster."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request


# This is public dependency metadata, not an inventory of installed services.
# Kubernetes follows its reviewed minor; kubeadm owns the DNS/etcd/pause bundle.
PROJECTS = {
    "KUBERNETES_VERSION": "kubernetes/kubernetes",
    "CONTAINERD_VERSION": "containerd/containerd",
    "RUNC_VERSION": "opencontainers/runc",
    "CNI_PLUGINS_VERSION": "containernetworking/plugins",
    "FLUX_VERSION": "fluxcd/flux2",
    "HELM_VERSION": "helm/helm",
    "CLOUDFLARED_HOST_VERSION": "cloudflare/cloudflared",
    "KUSTOMIZE_VERSION": "kubernetes-sigs/kustomize",
    "KIND_VERSION": "kubernetes-sigs/kind",
    "KUBECONFORM_VERSION": "yannh/kubeconform",
    "CONFTEST_VERSION": "open-policy-agent/conftest",
    "GITLEAKS_VERSION": "gitleaks/gitleaks",
    "TRIVY_VERSION": "aquasecurity/trivy",
    "SYFT_VERSION": "anchore/syft",
    "COSIGN_VERSION": "sigstore/cosign",
    "ORAS_VERSION": "oras-project/oras",
    "ACTIONLINT_VERSION": "rhysd/actionlint",
    "HADOLINT_VERSION": "hadolint/hadolint",
    "SHELLCHECK_VERSION": "koalaman/shellcheck",
}
VERSION = re.compile(r"(?:kustomize/)?v?([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})")


def version(value):
    """Accept only stable numeric release tags, never prereleases or ranges."""
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("invalid stable version")
    return tuple(int(part) for part in match.groups())


def read_pins(text):
    """Read the public registry as data and reject duplicate or absent inputs."""
    pins = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value or key in pins:
            raise ValueError("invalid pin registry")
        pins[key] = value
    for key in PROJECTS:
        version(pins[key])
    if not re.fullmatch(r"v[0-9]+\.[0-9]+", pins["KUBERNETES_MINOR"]):
        raise ValueError("invalid Kubernetes support line")
    if pins["CLOUDFLARED_TAG"] != pins["CLOUDFLARED_HOST_VERSION"]:
        raise ValueError("connector pins disagree")
    return pins


class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    """Only the credentialless official Kubernetes CDN redirect is expected."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        prefix = "https://cdn.dl.k8s.io/release/"
        if request.get_header("Authorization") or not new_url.startswith(prefix):
            raise ValueError("unexpected upstream redirect")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def download(url):
    """Bound public reads; the Actions token goes only to the GitHub API."""
    headers = {"User-Agent": "platform-software-currency"}
    if url.startswith("https://api.github.com/repos/"):
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
    elif not url.startswith("https://dl.k8s.io/release/stable-"):
        raise ValueError("unexpected upstream origin")
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(DownloadRedirect())
    with opener.open(request, timeout=20) as response:
        if response.status != 200:
            raise ValueError("upstream response was not successful")
        data = response.read(1_000_001)
    if not data or len(data) > 1_000_000:
        raise ValueError("upstream response size is invalid")
    return data


def check(key, pins, fetch=download):
    """A failed lookup is UNKNOWN; a newer stable candidate requires review."""
    repository = PROJECTS[key]
    current = pins[key]
    try:
        release = json.loads(fetch(f"https://api.github.com/repos/{repository}/releases/latest"))
        latest = release["tag_name"]
        if release["draft"] is not False or release["prerelease"] is not False:
            raise ValueError("release is not stable")
        if release["html_url"] != f"https://github.com/{repository}/releases/tag/{latest}":
            raise ValueError("release identity mismatch")
        version(latest)
        target = latest
        if key == "KUBERNETES_VERSION":
            minor = pins["KUBERNETES_MINOR"][1:]
            target = fetch(f"https://dl.k8s.io/release/stable-{minor}.txt").decode("ascii").strip()
            track = tuple(int(part) for part in minor.split("."))
            if version(target)[:2] != track or version(current)[:2] != track:
                raise ValueError("Kubernetes support line mismatch")
        state = "CURRENT" if version(current) == version(target) else "UPDATE"
        if version(current) > version(target):
            raise ValueError("pin is newer than the upstream stable channel")
        return key, current, target, latest, state
    except (KeyError, TypeError, ValueError, OSError, urllib.error.URLError):
        # Never print API bodies, headers, credentials or exception details.
        return key, current, "unverified", "unverified", "UNKNOWN"


def main():
    """Exit nonzero on drift or incomplete evidence, independently of PR CI."""
    try:
        root = Path(__file__).resolve().parents[2]
        pins = read_pins((root / "versions.env").read_text(encoding="utf-8"))
    except (OSError, KeyError, ValueError):
        print("Software currency: invalid public pin registry")
        return 1
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda key: check(key, pins), PROJECTS))
    print("| Pin | Committed | Update candidate | Upstream latest | Result |")
    print("| --- | --- | --- | --- | --- |")
    for row in rows:
        print("| " + " | ".join(row) + " |")
    print("\nKubernetes stays on the reviewed minor. Its kubeadm DNS/etcd/pause bundle and matching CRI tools move through the upgrade procedure.")
    print("Flux controller versions move with the Flux bundle. Frozen selector build inputs retain their reviewed identity until retirement.")
    print("This checks committed dependency pins; installed versions and health require separate operator evidence.")
    return int(any(row[-1] != "CURRENT" for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
