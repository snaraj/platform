"""Offline contract for the live exposure gate's fixed site inventory.

scripts/verify-exposure.sh is owner-run against the public edge and cannot run
in CI. These tests source it with --help (which defines its functions and
prints usage, touching no network), replace curl with a shell function, and
drive the real input validation and identity assertion so the site inventory
is proven by behaviour rather than by grepping the file (issue #422).
"""

import shutil
import subprocess
import unittest
from pathlib import Path

from .support import required_tool

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify-exposure.sh"
BASH = shutil.which("bash")
SITES = ("naranjo.online", "lidersea.com", "hospedajedonlolo.com")
# Each site's served <title>: the two Svelte sites title themselves with their
# domain; the third serves the owner's delivered page and its own title.
TITLES = {
    "naranjo.online": "naranjo.online",
    "lidersea.com": "lidersea.com",
    "hospedajedonlolo.com": "Hospedaje Don Lolo \u00b7 Granja Integral",
}


def own_body(site):
    """The root body a healthy site serves, as far as identity is concerned."""
    if site == "hospedajedonlolo.com":
        return '<title>{}</title> <form id="booking">'.format(TITLES[site])
    return "<title>{}</title> data-static-fallback Hello World!".format(site)

# A canned edge: every response a healthy site gives, with the root body taken
# from $BODY so each test chooses what the apex serves.
FAKE_CURL = r"""
curl() {
  case " $* " in
    *" --write-out "*) printf 200 ;;
    *" --head "*) printf 'cf-ray: x\ncontent-security-policy: x\nstrict-transport-security: x\nx-content-type-options: x\n' ;;
    *"/readyz"*) printf ok ;;
    *) printf '%s' "$BODY" ;;
  esac
}
"""


@unittest.skipUnless(BASH, "bash is unavailable")
class VerifyExposureInventoryTests(unittest.TestCase):
    def _run(self, body, env=""):
        program = (
            ". '{script}' --help >/dev/null\n"
            "PYTHON_BIN=python3\n"
            "{fake}\n"
            "{body}\n"
        ).format(script=SCRIPT, fake=FAKE_CURL, body=body)
        return subprocess.run(
            [required_tool(BASH, "bash"), "-c", env + program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

    def test_the_approved_inventory_is_exactly_the_three_sites(self):
        completed = self._run('printf "%s\\n" "$APPROVED_HOSTNAMES"')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.split(), list(SITES))

    def test_an_unexpected_hostname_must_be_a_subdomain_of_an_approved_zone(self):
        for hostname, accepted in (
            ("probe.hospedajedonlolo.com", True),
            ("probe.lidersea.com", True),
            ("hospedajedonlolo.com", False),
            ("probe.hospedajedonlolo.com.example", False),
            ("probe.example.com", False),
        ):
            with self.subTest(hostname=hostname):
                completed = self._run(
                    "validate_inputs",
                    env="export HOME_PUBLIC_IP=192.0.2.10 "
                    "UNEXPECTED_PUBLIC_HOSTNAME='{}'\n".format(hostname),
                )
                self.assertEqual(completed.returncode == 0, accepted, completed.stderr)

    def test_each_site_must_serve_only_its_own_identity(self):
        for site in SITES:
            with self.subTest(site=site, leak=None):
                completed = self._run(
                    "assert_site_identity '{}'".format(site),
                    env="export BODY='{}'\n".format(own_body(site)),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            for other in SITES:
                if other == site:
                    continue
                with self.subTest(site=site, leak=other):
                    leaked = own_body(site) + " <title>{}</title>".format(TITLES[other])
                    completed = self._run(
                        "assert_site_identity '{}'".format(site),
                        env="export BODY='{}'\n".format(leaked),
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(other, completed.stderr)

    def test_the_delivered_page_is_held_to_its_own_markers(self):
        # The third site serves the owner's delivered page byte for byte, so it
        # is identified by that page's own title and booking form; neither the
        # Svelte sites' domain title nor their build markers may stand in.
        site = "hospedajedonlolo.com"
        for label, body in (
            ("domain title instead of the delivered one",
             "<title>hospedajedonlolo.com</title> <form id=\"booking\">"),
            ("Svelte markers instead of the booking form",
             "<title>{}</title> data-static-fallback Hello World!".format(TITLES[site])),
        ):
            with self.subTest(case=label):
                completed = self._run(
                    "assert_site_identity '{}'".format(site),
                    env="export BODY='{}'\n".format(body),
                )
                self.assertNotEqual(completed.returncode, 0, label)


@unittest.skipUnless(BASH, "bash is unavailable")
class UnexpectedHostnameDenialTests(unittest.TestCase):
    """The edge's answer to an unapproved name must carry no tenant content.

    This drives the real assert_unexpected_hostname_denied, not the approved
    identity check above: the edge answers the unexpected name with a 4xx
    body, and each site's markers must be refused in that body on their own.
    """

    def _deny(self, body, status="404"):
        program = (
            ". '{script}' --help >/dev/null\n"
            "curl() {{ printf '%s\\n%s' \"$BODY\" \"$STATUS\"; }}\n"
            "assert_unexpected_hostname_denied naranjo.online\n"
        ).format(script=SCRIPT)
        return subprocess.run(
            [required_tool(BASH, "bash"), "-c", program],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env={
                "PATH": "/usr/bin:/bin",
                "BODY": body,
                "STATUS": status,
                "UNEXPECTED_PUBLIC_HOSTNAME": "probe.hospedajedonlolo.com",
            },
        )

    def test_a_clean_denial_passes(self):
        completed = self._deny("<html><body>not found</body></html>")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PASS unexpected hostname denied", completed.stdout)

    def test_a_served_page_is_not_a_denial(self):
        completed = self._deny("<html></html>", status="200")
        self.assertNotEqual(completed.returncode, 0)

    def test_each_tenant_marker_in_the_denial_body_is_refused(self):
        markers = {
            "third-site delivered title": "<title>{}</title>".format(TITLES["hospedajedonlolo.com"]),
            "third-site booking form": '<form id="booking">',
            "third-site domain title": "<title>hospedajedonlolo.com</title>",
            "naranjo title": "<title>naranjo.online</title>",
            "lidersea title": "<title>lidersea.com</title>",
            "Svelte fallback marker": "data-static-fallback",
        }
        for label, marker in markers.items():
            with self.subTest(marker=label):
                completed = self._deny("<html>{}</html>".format(marker))
                self.assertNotEqual(completed.returncode, 0, label)
                self.assertIn("received approved tenant content", completed.stderr)


if __name__ == "__main__":
    unittest.main()
