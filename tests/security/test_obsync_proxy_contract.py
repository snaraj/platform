"""Anchor the actual render, budget and mandatory gates independently of Rego."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest

from .test_namespace_capacity_contract import committed_quota
from .testsupport.capacity_model import parse_cpu, parse_memory

ROOT = Path(__file__).resolve().parents[2]
PROXY = ROOT / "kubernetes/platform/obsync-tls-proxy"


class ObsyncProxyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rendered = subprocess.run(["kustomize", "build", str(PROXY)], capture_output=True, text=True, check=True, timeout=30).stdout
        cls.documents = json.loads(subprocess.run(["conftest", "parse", "-"], input=rendered, capture_output=True, text=True, check=True, timeout=30).stdout)
        cls.by_kind = {obj["kind"]: obj for obj in cls.documents}

    def test_exact_render_inventory_and_reference_closure(self):
        self.assertEqual(len(self.documents), 5)
        self.assertEqual(set(self.by_kind), {"ServiceAccount", "ConfigMap", "Service", "Deployment", "NetworkPolicy"})
        for obj in self.documents:
            self.assertEqual(obj["metadata"]["namespace"], "obsidian")
            if obj["kind"] != "ConfigMap":
                self.assertEqual(obj["metadata"]["name"], "obsync-tls-proxy")
        pod = self.by_kind["Deployment"]["spec"]["template"]["spec"]
        self.assertEqual(pod["volumes"][0]["configMap"]["name"], self.by_kind["ConfigMap"]["metadata"]["name"])
        self.assertEqual(pod["serviceAccountName"], self.by_kind["ServiceAccount"]["metadata"]["name"])
        self.assertIs(self.by_kind["ServiceAccount"]["automountServiceAccountToken"], False)
        self.assertEqual(self.by_kind["ConfigMap"]["data"], {"nginx.conf": (PROXY / "nginx.conf").read_text()})
        self.assertEqual(hashlib.sha256((PROXY / "nginx.conf").read_bytes()).hexdigest(), "498a0c70350405c5519f51e4cd867e37ab3bd4720a86fe1eeaa91e485d7d5dd9")

    def test_proxy_and_app_replacement_slots_fit_exact_quota(self):
        deployment = self.by_kind["Deployment"]["spec"]
        self.assertEqual(deployment["replicas"], 1)
        self.assertEqual(deployment["strategy"], {"type": "Recreate"})
        containers = deployment["template"]["spec"]["containers"]
        self.assertEqual(len(containers), 1)
        resources = containers[0]["resources"]
        quota = committed_quota("obsidian")
        self.assertEqual(int(quota["pods"]), 4)
        for bound, app_cpu, app_memory in (("requests", "100m", "64Mi"), ("limits", "2", "1Gi")):
            self.assertEqual(parse_cpu(quota[bound + ".cpu"]), 2 * (parse_cpu(app_cpu) + parse_cpu(resources[bound]["cpu"])))
            self.assertEqual(parse_memory(quota[bound + ".memory"]), 2 * (parse_memory(app_memory) + parse_memory(resources[bound]["memory"])))

    def test_manifest_and_policy_share_versioned_pin(self):
        pins = re.findall(r"(?m)^OBSYNC_TLS_PROXY_IMAGE=(\S+)$", (ROOT / "versions.env").read_text())
        self.assertEqual(len(pins), 1)
        self.assertRegex(pins[0], r"^docker\.io/nginxinc/nginx-unprivileged:[a-z0-9.-]+@sha256:[0-9a-f]{64}$")
        self.assertEqual(self.by_kind["Deployment"]["spec"]["template"]["spec"]["containers"][0]["image"], pins[0])
        self.assertIn('obsync_proxy_image := "' + pins[0] + '"', (ROOT / "policies/conftest/obsync_tls_proxy.rego").read_text())

    def test_new_surfaces_reach_mandatory_gates(self):
        renderer = (ROOT / "scripts/render-manifests.sh").read_text()
        targets = re.search(r"declare -a KUSTOMIZE_TARGETS=\(\n(.*?)\n\)", renderer, re.S)
        self.assertIsNotNone(targets)
        self.assertIn("  kubernetes/platform/obsync-tls-proxy\n", targets.group(1) + "\n")
        self.assertRegex((ROOT / "scripts/test-policy-fixtures.sh").read_text(), r'(?m)^conftest verify --policy "\$policy"$')
        workflow = json.loads(subprocess.run(["conftest", "parse", str(ROOT / ".github/workflows/pull-request.yml")], capture_output=True, text=True, check=True, timeout=30).stdout)
        job = workflow["jobs"]["repository-and-infrastructure"]
        self.assertNotIn("if", job)
        steps = job["steps"]
        smoke = [step for step in steps if step.get("name") == "Validate the private obsync TLS transport"]
        self.assertEqual(smoke, [{"name": "Validate the private obsync TLS transport", "run": "make check-obsync-proxy"}])
        scans = [step for step in steps if step.get("name") == "Scan the pinned obsync proxy image"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(set(scans[0]), {"name", "run"})
        scan = scans[0]["run"]
        self.assertEqual(hashlib.sha256(scan.encode()).hexdigest(), "2c324c9929a1dc90e019ef6e59bb85e195957f77fad8a5bc918fdee553b07e73")
        self.assertTrue(scan.startswith("set -euo pipefail\n"))
        self.assertIn("for platform in linux/amd64 linux/arm64; do\n", scan)
        self.assertIn('trivy image --image-src remote --platform "$platform"', scan)
        self.assertIn('--exit-code 1 --scanners vuln --severity HIGH,CRITICAL "$proxy_image"', scan)
        self.assertNotIn("--ignore-unfixed", scan)
        self.assertNotIn("||", scan)
        self.assertRegex((ROOT / "Makefile").read_text(), r'(?m)^check-obsync-proxy:\n\t@\$\(PYTHON\) -B tests/obsync_proxy_smoke.py$')
        for filename, expected in (
            ("obsync_storage_test.rego", {"test_obsync_claim_pair_allowed", "test_obsync_claim_scope_refused", "test_bare_pod_does_not_inherit_claim_exception"}),
            ("obsync_tls_proxy_test.rego", {"test_proxy_positive", "test_proxy_changed_pod_fields_refused", "test_proxy_additional_pod_field_refused", "test_proxy_exception_does_not_follow_relabelling", "test_proxy_network_fields_refused", "test_additive_sibling_network_policy_refused", "test_proxy_service_widening_refused", "test_proxy_unreviewed_config_refused"}),
        ):
            source = (ROOT / "policies/conftest" / filename).read_text()
            self.assertEqual(set(re.findall(r"(?m)^(test_\w+) if", source)), expected)
