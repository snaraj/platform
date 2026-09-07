"""Release drift must be visible without granting updater or cluster authority."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("currency", ROOT / "scripts/ci/check_software_currency.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def release(repository, tag="v1.2.3", **extra):
    return json.dumps({"tag_name": tag, "draft": False, "prerelease": False,
                       "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
                       **extra}).encode()


class SoftwareCurrencyTests(unittest.TestCase):
    def setUp(self):
        self.pins = {key: "v1.2.3" for key in MODULE.PROJECTS}
        self.pins.update(KUBERNETES_MINOR="v1.36", KUBERNETES_VERSION="v1.36.4",
                         CLOUDFLARED_TAG="v1.2.3")

    def test_current_update_and_ahead_are_distinct(self):
        for tag, expected in (("v1.2.3", "CURRENT"), ("v1.2.4", "UPDATE"),
                              ("v1.3.0", "UPDATE"), ("v1.2.2", "UNKNOWN")):
            with self.subTest(tag=tag):
                row = MODULE.check("RUNC_VERSION", self.pins,
                                   lambda url: release("opencontainers/runc", tag))
                self.assertEqual(row[-1], expected)

    def test_versions_compare_numerically_and_reject_nonstable_tags(self):
        self.assertGreater(MODULE.version("v1.10.0"), MODULE.version("v1.9.9"))
        self.assertEqual(MODULE.version("kustomize/v5.8.1"), (5, 8, 1))
        for bad in ("v1.2.3-rc.1", "1.2", "latest", "1.2.3\n", "v١.2.3", "other/v1.2.3", None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                MODULE.version(bad)

    def test_failed_or_foreign_release_is_unknown_without_raw_diagnostics(self):
        values = [b"not JSON", b"[]", b"null", b"{}"]
        for extra in ({"draft": True}, {"draft": None}, {"prerelease": True},
                      {"html_url": "https://example.invalid/release"}, {"tag_name": "v1.2.4-rc.1"}):
            values.append(release("opencontainers/runc", **extra))
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(MODULE.check("RUNC_VERSION", self.pins, lambda url: value)[-1], "UNKNOWN")
        def unavailable(url):
            raise OSError("response-body-must-not-be-printed")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(MODULE.check("RUNC_VERSION", self.pins, unavailable)[-1], "UNKNOWN")
        self.assertEqual(output.getvalue(), "")

    def test_kubernetes_reports_new_minor_without_selecting_it(self):
        calls = []
        def fetch(url):
            calls.append(url)
            if url.startswith("https://api.github.com/"):
                return release("kubernetes/kubernetes", "v1.37.0")
            self.assertEqual(url, "https://dl.k8s.io/release/stable-1.36.txt")
            return b"v1.36.4\n"
        self.assertEqual(MODULE.check("KUBERNETES_VERSION", self.pins, fetch)[2:],
                         ("v1.36.4", "v1.37.0", "CURRENT"))
        self.assertEqual(len(calls), 2)
        self.pins["KUBERNETES_VERSION"] = "v1.36.3"
        self.assertEqual(MODULE.check("KUBERNETES_VERSION", self.pins, fetch)[-1], "UPDATE")
        self.pins["KUBERNETES_VERSION"] = "v1.37.0"
        self.assertEqual(MODULE.check("KUBERNETES_VERSION", self.pins, fetch)[-1], "UNKNOWN")

    def test_kubernetes_channel_cannot_cross_the_reviewed_minor(self):
        def fetch(url):
            return release("kubernetes/kubernetes", "v1.37.0") if "api.github.com" in url else b"v1.37.0"
        self.assertEqual(MODULE.check("KUBERNETES_VERSION", self.pins, fetch)[-1], "UNKNOWN")

    def test_pin_registry_rejects_duplicates_missing_values_and_split_connectors(self):
        text = "\n".join(f"{key}={value}" for key, value in self.pins.items())
        self.assertEqual(MODULE.read_pins(text), self.pins)
        for bad in (text + "\nRUNC_VERSION=v1.2.3", text.replace("RUNC_VERSION=v1.2.3", ""),
                    text.replace("RUNC_VERSION=v1.2.3", "RUNC_VERSION="),
                    text.replace("CLOUDFLARED_TAG=v1.2.3", "CLOUDFLARED_TAG=v1.2.4"),
                    text.replace("KUBERNETES_MINOR=v1.36", "KUBERNETES_MINOR=../other")):
            with self.subTest(bad=bad), self.assertRaises((ValueError, KeyError)):
                MODULE.read_pins(bad)

    def test_network_reads_are_bounded_and_token_is_github_only(self):
        requests = []
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit):
                self.assert_limit = limit
                return b"v1.36.4"
        response = Response()
        class Opener:
            def open(self, request, timeout):
                requests.append((request, timeout))
                return response
        with patch.object(MODULE.urllib.request, "build_opener", return_value=Opener()), \
                patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-example"}, clear=True):
            MODULE.download("https://api.github.com/repos/opencontainers/runc/releases/latest")
            MODULE.download("https://dl.k8s.io/release/stable-1.36.txt")
            with self.assertRaises(ValueError):
                MODULE.download("https://example.invalid/releases/latest")
        self.assertEqual(requests[0][0].get_header("Authorization"), "Bearer synthetic-example")
        self.assertIsNone(requests[1][0].get_header("Authorization"))
        self.assertEqual([timeout for _, timeout in requests], [20, 20])
        self.assertEqual(response.assert_limit, 1_000_001)

    def test_non_success_empty_and_oversized_downloads_fail(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return self.data
        for status, data in ((201, b"{}"), (200, b""), (200, b"x" * 1_000_001)):
            response = Response()
            response.status, response.data = status, data
            with patch.object(MODULE.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(ValueError):
                    MODULE.download("https://api.github.com/repos/opencontainers/runc/releases/latest")

    def test_redirects_cannot_move_the_api_token_or_leave_the_official_cdn(self):
        redirect = MODULE.DownloadRedirect()
        source = "https://dl.k8s.io/release/stable-1.36.txt"
        target = "https://cdn.dl.k8s.io/release/stable-1.36.txt"
        request = urllib.request.Request(source)
        self.assertEqual(redirect.redirect_request(request, None, 302, "", {}, target).full_url, target)
        for url in ("http://cdn.dl.k8s.io/release/stable-1.36.txt", "https://example.invalid/file"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                redirect.redirect_request(request, None, 302, "", {}, url)
        request.add_header("Authorization", "Bearer synthetic-example")
        with self.assertRaises(ValueError):
            redirect.redirect_request(request, None, 302, "", {}, target)

    def test_main_exits_red_for_drift_and_unknown(self):
        for state, expected in (("CURRENT", 0), ("UPDATE", 1), ("UNKNOWN", 1)):
            with patch.object(MODULE, "check", side_effect=lambda key, pins: (key, "1.2.3", "1.2.3", "1.2.3", state)), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(MODULE.main(), expected)
            self.assertEqual(output.getvalue().count("| " + state + " |"), 19)
        with patch.object(MODULE, "read_pins", side_effect=ValueError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(MODULE.main(), 1)

    def test_daily_job_preserves_pipe_failure_and_read_only_permissions(self):
        workflow = (ROOT / ".github/workflows/software-currency.yml").read_text()
        self.assertIn("cron: '41 10 * * *'", workflow)
        self.assertIn("timeout-minutes: 5", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn(": write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("shell: bash", workflow)
        self.assertIn("python3 -I -B scripts/ci/check_software_currency.py | tee", workflow)
