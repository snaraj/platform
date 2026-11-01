"""Release-mode, release-gate and namespace coverage for the third website.

Issue #422. The tenant policy has allow and deny fixtures for every table the
third site joined. Three surfaces had no control at all:
- the RELEASE policy;
- the release-check's quota set;
- the committed Namespace file, which no gate renders.

Each gets its own control here. Without them, dropping the site from any of
those surfaces, or weakening its Pod Security labels, passed every gate.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .support import load_script, required_tool

ROOT = Path(__file__).resolve().parents[2]
CONFTEST = shutil.which("conftest")
RELEASE_POLICY = ROOT / "policies/release-conftest"
VALIDATOR = load_script("validate_repository.py")
SITE = "hospedajedonlolo-com"
SITE_EVIDENCE = Path("docs/audits/2026-08-22-site-capacity-evidence.md")


def release_denials(document):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.yaml"
        path.write_text(document, encoding="utf-8")
        completed = subprocess.run(
            [required_tool(CONFTEST, "conftest"), "test", "--policy",
             str(RELEASE_POLICY), "--output", "json", "--no-color", str(path)],
            capture_output=True, text=True, check=False, cwd=ROOT,
        )
    report = json.loads(completed.stdout)
    return sorted(
        failure.get("msg", "")
        for result in report
        for failure in result.get("failures") or []
    )


DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: hospedajedonlolo-com
  namespace: hospedajedonlolo-com
  annotations:
    platform.snaraj.dev/deployment-ready: "{ready}"
spec:
  template:
    spec:
      containers:
        - name: hospedajedonlolo-com
          image: ghcr.io/snaraj/hospedajedonlolo-com@sha256:{digest}
"""

RELEASE = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: hospedajedonlolo-com
  namespace: hospedajedonlolo-com
spec:
  suspend: false
  values:
{values}
"""


@unittest.skipUnless(CONFTEST, "conftest is required")
class ThirdSiteReleasePolicyTests(unittest.TestCase):
    def test_a_ready_site_deployment_and_release_are_admitted(self):
        self.assertEqual(release_denials(DEPLOYMENT.format(ready="true", digest="1" * 64)), [])
        self.assertEqual(release_denials(RELEASE.format(values="    deploymentReady: true")), [])

    def test_an_unready_site_deployment_is_refused(self):
        self.assertEqual(
            release_denials(DEPLOYMENT.format(ready="false", digest="1" * 64)),
            ["Deployment hospedajedonlolo-com is not marked ready"],
        )

    def test_release_values_beyond_the_readiness_scalar_are_refused(self):
        self.assertEqual(
            release_denials(RELEASE.format(values="    deploymentReady: true\n    replicas: 2")),
            ["HelmRelease hospedajedonlolo-com values must contain exactly deploymentReady: true"],
        )

    def test_a_suspended_site_reconciler_is_not_a_release(self):
        kustomization = (
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\n"
            "kind: Kustomization\n"
            "metadata:\n  name: hospedajedonlolo-com\n  namespace: flux-system\n"
            "spec:\n  suspend: true\n"
        )
        self.assertEqual(
            release_denials(kustomization),
            ["Kustomization hospedajedonlolo-com remains suspended"],
        )

    def test_the_budget_is_bound_to_the_shared_site_evidence(self):
        quota = (
            "apiVersion: v1\nkind: ResourceQuota\n"
            "metadata:\n  name: namespace-budget\n  namespace: hospedajedonlolo-com\n"
            "  annotations:\n"
            "    platform.snaraj.dev/readiness: reviewed-pi-capacity\n"
            "    platform.snaraj.dev/capacity-evidence-sha256: {evidence}\n"
            "spec:\n  hard:\n    pods: \"6\"\n    requests.cpu: 150m\n"
            "    requests.memory: 192Mi\n    limits.cpu: 1200m\n    limits.memory: 768Mi\n"
        )
        shared = VALIDATOR.REVIEWED_NAMESPACE_CAPACITY["lidersea-com"]
        evidence = __import__("hashlib").sha256(
            (ROOT / shared[0]).read_bytes()
        ).hexdigest()
        self.assertEqual(release_denials(quota.format(evidence=evidence)), [])
        self.assertEqual(
            release_denials(quota.format(evidence="0" * 64)),
            ["workload capacity gate remains closed or lacks a hash-bound reviewed "
             "budget in namespace hospedajedonlolo-com"],
        )


@unittest.skipUnless(CONFTEST, "conftest is required")
class CommittedNamespaceTests(unittest.TestCase):
    """The bootstrap-applied Namespace file, under the tenant policy.

    `kubernetes/platform/prerequisites/namespaces.yaml` sits outside every
    rendered Kustomize root, so no render ever fed it to the policy that
    requires restricted Pod Security on tenant namespaces.
    """

    PATH = ROOT / "kubernetes/platform/prerequisites/namespaces.yaml"

    def test_every_committed_namespace_passes_the_tenant_policy(self):
        completed = subprocess.run(
            [required_tool(CONFTEST, "conftest"), "test", "--policy",
             str(ROOT / "policies/conftest"), "--output", "json", "--no-color",
             str(self.PATH)],
            capture_output=True, text=True, check=False, cwd=ROOT,
        )
        failures = [
            failure.get("msg", "")
            for result in json.loads(completed.stdout)
            for failure in result.get("failures") or []
        ]
        self.assertEqual(failures, [])

    def test_the_committed_namespaces_are_exactly_the_tenant_set(self):
        names = re.findall(r"(?m)^  name: (\S+)$", self.PATH.read_text(encoding="utf-8"))
        rego = (ROOT / "policies/conftest/kubernetes.rego").read_text(encoding="utf-8")
        tenants = re.search(r"(?m)^tenant_namespaces := \{([^}]*)\}$", rego)
        self.assertIsNotNone(tenants)
        self.assertEqual(sorted(names), sorted(re.findall(r'"([a-z0-9-]+)"', tenants.group(1))))
        self.assertIn(SITE, names)


class ReleaseGateSiteQuotaSetTests(unittest.TestCase):
    """The release-check's site set is the set bound to the shared evidence.

    `scripts/release-gate.sh --release-check` compares every rendered site
    budget against ONE reviewed discovery hash. Its site set therefore has to
    equal the namespaces the repository validator binds to the shared site
    evidence document — a site missing from it is a budget the release check
    silently never reads.
    """

    def test_the_release_check_reads_every_site_bound_to_the_shared_evidence(self):
        script = (ROOT / "scripts/release-gate.sh").read_text(encoding="utf-8")
        matched = re.search(r"(?m)^site_namespaces = \{([^}]*)\}$", script)
        self.assertIsNotNone(matched, "the release-check site set disappeared")
        declared = set(re.findall(r'"([a-z0-9-]+)"', matched.group(1)))
        shared = {
            namespace
            for namespace, (evidence, _hard) in VALIDATOR.REVIEWED_NAMESPACE_CAPACITY.items()
            if evidence == SITE_EVIDENCE
        }
        self.assertIn(SITE, shared)
        self.assertEqual(declared, shared)
        self.assertIn("len(site_quotas) != len(site_namespaces)", script)


if __name__ == "__main__":
    unittest.main()
