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


if __name__ == "__main__":
    unittest.main()
