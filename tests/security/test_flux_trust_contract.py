"""Pin the isolated public trust store across the complete controller render.

The checked-in bytes are public CA certificates, never a host trust-store copy.
Both Unix Go overrides are load-bearing: either default path can restore an
excluded anchor. Runtime-chain proof is separate from these offline contracts.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import ssl
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLERS = ROOT / "kubernetes/flux-system/controllers"
BUNDLE_SHA256 = "00f6a1aad627fd3f6c1bb16065850c7721949e489b65a26a3042091720c7f02e"
EXCLUDED_SHA256 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
NAMES = tuple("flux-controller-ca-00f6a1aad627-" + part for part in "ab")
DEPLOYMENTS = {"source-controller", "kustomize-controller", "helm-controller"}


class FluxTrustContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool = shutil.which("kustomize")
        if tool is None:
            raise unittest.SkipTest("kustomize is required for the full rendered trust contract")
        result = subprocess.run([tool, "build", str(CONTROLLERS)], capture_output=True, text=True, check=True)
        cls.documents = re.split(r"(?m)^---\s*$", result.stdout)

    def test_exact_public_bundle_and_immutable_objects(self):
        parts = {}
        for document in self.documents:
            if not re.search(r"(?m)^kind: ConfigMap$", document):
                continue
            name = re.search(r"(?m)^  name: (.+)$", document)
            self.assertIsNotNone(name)
            self.assertIn(name[1], NAMES)
            self.assertNotIn(name[1], parts, "duplicate trust object")
            key = "roots-" + name[1][-1] + ".pem"
            expected_prefix = "apiVersion: v1\ndata:\n  " + key + ": |\n"
            self.assertTrue(document.strip().startswith(expected_prefix))
            match = re.search(r"(?m)^  " + re.escape(key) + r": \|\n((?:    .*\n)+)", document)
            self.assertIsNotNone(match)
            pem = "".join(line[4:] + "\n" for line in match[1].splitlines())
            expected = expected_prefix + match[1] + (
                "immutable: true\nkind: ConfigMap\nmetadata:\n  labels:\n"
                "    app.kubernetes.io/instance: flux-system\n"
                "    app.kubernetes.io/part-of: flux\n"
                "  name: " + name[1] + "\n  namespace: flux-system\n"
            )
            self.assertEqual(document.strip(), expected.strip(), "extra or mutable projected data")
            self.assertLessEqual(len(document.encode()), 128 * 1024)
            parts[name[1]] = pem
        self.assertEqual(set(parts), set(NAMES))
        combined = "".join(parts[name] for name in NAMES)
        self.assertEqual(hashlib.sha256(combined.encode()).hexdigest(), BUNDLE_SHA256)
        certificates = re.findall(r"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----\n", combined, re.S)
        self.assertEqual("".join(certificates), combined, "non-certificate data in bundle")
        fingerprints = [hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() for cert in certificates]
        self.assertEqual(len(fingerprints), 118)
        self.assertEqual(len(set(fingerprints)), 118)
        self.assertNotIn(EXCLUDED_SHA256, fingerprints)

    def test_every_controller_uses_only_the_readonly_projected_bundle(self):
        found = set()
        expected_volume = """      - name: controller-ca
        projected:
          defaultMode: 292
          sources:
          - configMap:
              items:
              - key: roots-a.pem
                path: roots-a.pem
              name: flux-controller-ca-00f6a1aad627-a
          - configMap:
              items:
              - key: roots-b.pem
                path: roots-b.pem
              name: flux-controller-ca-00f6a1aad627-b"""
        for document in self.documents:
            if not re.search(r"(?m)^kind: Deployment$", document):
                continue
            name = re.search(r"(?m)^  name: (.+)$", document)[1]
            self.assertIn(name, DEPLOYMENTS)
            self.assertNotIn(name, found)
            found.add(name)
            for variable, value in (("SSL_CERT_FILE", "/etc/flux-trust/roots-a.pem"),
                                    ("SSL_CERT_DIR", "/etc/flux-trust")):
                self.assertEqual(document.count("name: " + variable), 1)
                self.assertIn("        - name: " + variable + "\n          value: " + value + "\n", document)
            self.assertEqual(document.count("mountPath: /etc/flux-trust"), 1)
            self.assertIn("        - mountPath: /etc/flux-trust\n          name: controller-ca\n          readOnly: true\n", document)
            self.assertEqual(document.count("name: controller-ca"), 2)
            # The projected volume is last: equality pins its entire shape,
            # including the absence of optional inputs or additional roots.
            offset = document.index("      - name: controller-ca\n")
            self.assertEqual(document[offset:].strip(), expected_volume.strip())
        self.assertEqual(found, DEPLOYMENTS)
