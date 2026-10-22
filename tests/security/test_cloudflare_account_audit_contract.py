#!/usr/bin/env python3
"""Regression battery for the owner-run Cloudflare ``cf`` account audit."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from .support import required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "cloudflare-account-audit.sh"
READER = REPO_ROOT / "scripts" / "cloudflare_cf_read.py"
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the audit script"

ACCOUNT_ID = "c" * 32
ZONE_A_ID = "a" * 32
ZONE_B_ID = "b" * 32


def synthetic_uuid(character: str) -> str:
    return "-".join(character * size for size in (8, 4, 4, 4, 12))


TUNNEL_A_ID = synthetic_uuid("1")
TUNNEL_B_ID = synthetic_uuid("2")
TOKEN_ID = "d" * 32
USER_ID = "e" * 32
OTHER_ACCOUNT_ID = "f" * 32
OTHER_ZONE_ID = "9" * 32
OTHER_USER_ID = "8" * 32
API_TOKEN = "short_lived_read_only_fixture_token_12345"
PRIVATE_TUNNEL_NAME = "private-customer-tunnel-do-not-print"

EXPECTED_OPERATIONS = {
    "zones-list": (("zones", "list"), "/zones"),
    "account-subscriptions": (
        ("accounts", "subscriptions", "get"),
        "/{account_or_zone}/{account_or_zone_id}/subscriptions",
    ),
    "user-subscriptions": (("user", "subscriptions", "get"), "/user/subscriptions"),
    "zone-subscription": (
        ("zones", "subscriptions", "get"),
        "/zones/{zone_id}/subscription",
    ),
    "billing-history": (
        ("accounts", "billing", "history", "list"),
        "/accounts/{account_id}/billing/history",
    ),
    "unpaid-invoices": (
        ("accounts", "billing", "getUnpaidInvoices"),
        "/accounts/{account_id}/billing/unpaid-invoice",
    ),
    "bad-debt": (
        ("accounts", "billing", "getBadDebt"),
        "/accounts/{account_id}/billing/bad-debt",
    ),
    "billing-usage-info-v1": (
        ("billing", "usage", "get-info-v1"),
        "/accounts/{account_id}/billable-usage/info",
    ),
    "billing-usage-v1": (
        ("billing", "usage", "get-v1"),
        "/accounts/{account_id}/billable-usage",
    ),
    "billable-metrics": (
        ("billing", "usage", "get-account-billable-metrics"),
        "/accounts/{account_id}/billable/usage/billable-metrics",
    ),
    "certificate-packs": (
        ("ssl", "certificate-packs", "list"),
        "/zones/{zone_id}/ssl/certificate_packs",
    ),
    "certificate-pack-quota": (
        ("ssl", "certificate-packs", "quota", "get"),
        "/zones/{zone_id}/ssl/certificate_packs/quota",
    ),
    "zone-setting": (
        ("zones", "settings", "get"),
        "/zones/{zone_id}/settings/{setting_id}",
    ),
    "dnssec": (("dns", "dnssec", "get"), "/zones/{zone_id}/dnssec"),
    "tunnels-list": (("tunnels", "list"), "/accounts/{account_id}/tunnels"),
    "tunnel-config": (
        ("tunnels", "config", "get"),
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
    ),
    "tunnel-connections": (
        ("tunnels", "connections", "list"),
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
    ),
    "private-routes": (
        ("network", "routes", "cidr", "list"),
        "/accounts/{account_id}/teamnet/routes",
    ),
    "warp-profiles": (
        ("zero-trust", "devices", "profiles", "custom", "list"),
        "/accounts/{account_id}/devices/policies",
    ),
    "dns-records": (
        ("dns", "records", "list"),
        "/zones/{zone_id}/dns_records",
    ),
    "user-token-verify": (("user", "tokens", "verify"), "/user/tokens/verify"),
    "user-token-get": (("user", "tokens", "get"), "/user/tokens/{token_id}"),
}
SCHEMA_PATHS = {command: path for command, path in EXPECTED_OPERATIONS.values()}


def fake_cf_source(mode: str, log_path: Path) -> str:
    template = """\
        #!/usr/bin/env python3
        from datetime import datetime, timedelta, timezone
        import json
        import os
        import sys

        MODE = __MODE__
        LOG = __LOG__
        SCHEMAS = __SCHEMAS__
        ZONE_A_ID = __ZONE_A_ID__
        ZONE_B_ID = __ZONE_B_ID__
        ACCOUNT_ID = __ACCOUNT_ID__
        TUNNEL_A_ID = __TUNNEL_A_ID__
        TUNNEL_B_ID = __TUNNEL_B_ID__
        TOKEN_ID = __TOKEN_ID__
        USER_ID = __USER_ID__
        OTHER_ACCOUNT_ID = __OTHER_ACCOUNT_ID__
        OTHER_ZONE_ID = __OTHER_ZONE_ID__
        OTHER_USER_ID = __OTHER_USER_ID__
        PRIVATE_TUNNEL_NAME = __PRIVATE_TUNNEL_NAME__

        def emit(value):
            print(json.dumps(value, separators=(",", ":")))

        def option(args, name, default=None):
            if name in args:
                return args[args.index(name) + 1]
            prefix = name + "="
            for item in args:
                if item.startswith(prefix):
                    return item[len(prefix):]
            return default

        def free_subscription(plan_id):
            if MODE == "subscription-plan-near-match":
                plan_id = "paid-but-free-looking"
            elif MODE == "subscription-plan-unknown":
                plan_id = "unknown-plan"
            elif MODE == "subscription-plan-wrong-endpoint":
                plan_id = {
                    "teams_free": "free",
                    "free": "teams_free",
                }[plan_id]
            rate_plan = {
                "id": plan_id,
                "is_contract": False,
                "externally_managed": False,
            }
            for field in ("is_contract", "externally_managed"):
                if MODE == f"subscription-{field}-true":
                    rate_plan[field] = True
                elif MODE == f"subscription-{field}-missing":
                    rate_plan.pop(field)
            result = {"price": 0, "rate_plan": rate_plan, "state": "Paid"}
            if MODE.startswith("subscription-state-"):
                state = MODE.removeprefix("subscription-state-")
                if state == "missing":
                    result.pop("state")
                else:
                    result["state"] = state
            return result

        args = sys.argv[1:]
        logged_args = ["<token-id>" if item == TOKEN_ID else item for item in args]
        with open(LOG, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "args": logged_args,
                "account": bool(os.environ.get("CLOUDFLARE_ACCOUNT_ID")),
                "token_present": bool(os.environ.get("CLOUDFLARE_API_TOKEN")),
            }) + "\\n")

        if args == ["--version"]:
            version = "v1.0.0-beta.4" if MODE == "old-version" else "v1.0.0-beta.5"
            print("cf " + version)
            raise SystemExit(0)

        if args and args[0] == "schema":
            command = tuple(args[1:])
            path = SCHEMAS.get(command)
            if path is None:
                raise SystemExit(7)
            targeted = command == ("zones", "list")
            method = "POST" if MODE == "write-schema" and targeted else "GET"
            if MODE == "path-schema" and targeted:
                path = "/unexpected"
            has_body = method != "GET" or (MODE == "body-schema" and targeted)
            emit({"httpMethod": method, "path": path, "hasRequestBody": has_body})
            raise SystemExit(0)

        runtime = list(args)
        page = int(option(runtime, "--page", "1"))

        if runtime[:2] == ["zones", "list"]:
            name = option(runtime, "--name")
            if MODE == "malformed-json":
                print("not-json")
            elif MODE == "repeat-page" or page == 1:
                zone_id = ZONE_A_ID if name == "naranjo.online" else ZONE_B_ID
                emit([{"id": zone_id, "name": name, "account": {"id": ACCOUNT_ID}, "plan": {"name": "Free Website"}, "status": "active"}])
            else:
                emit([])
        elif runtime[:3] == ["accounts", "subscriptions", "get"]:
            if MODE == "paid-subscription":
                emit([{
                    "price": 20,
                    "rate_plan": {
                        "id": "pro",
                        "is_contract": False,
                        "externally_managed": False,
                    },
                    "state": "Paid",
                }])
            elif MODE == "subscription-plan-account-uppercase":
                emit([free_subscription("TEAMS_FREE")])
            else:
                emit([free_subscription("teams_free")])
        elif runtime[:3] == ["user", "subscriptions", "get"]:
            emit([free_subscription("free")])
        elif runtime[:3] == ["zones", "subscriptions", "get"]:
            emit(free_subscription("free"))
        elif runtime[:4] == ["accounts", "billing", "history", "list"]:
            if MODE == "denied-billing":
                print("billing read denied", file=sys.stderr)
                raise SystemExit(13)
            if MODE == "positive-history" and page == 1:
                emit([{"amount": 15, "amount_to_pay": 0}])
            elif MODE == "negative-history" and page == 1:
                emit([{"amount": -1, "amount_to_pay": 0}])
            else:
                emit([])
        elif runtime[:3] == ["accounts", "billing", "getUnpaidInvoices"]:
            if MODE == "unpaid-invoice":
                emit({"invoices": [{"amount": 12.5, "amount_to_pay": 12.5}]})
            else:
                emit({"invoices": []})
        elif runtime[:3] == ["accounts", "billing", "getBadDebt"]:
            emit({"total_debt_amount": 12.5 if MODE == "bad-debt" else 0})
        elif runtime[:3] == ["billing", "usage", "get-info-v1"]:
            emit({"covered": True, "subscriptions": []})
        elif runtime[:3] == ["billing", "usage", "get-v1"]:
            if MODE == "billing-cost":
                emit([{
                    "BilledCost": 1,
                    "ContractedCost": 0,
                    "CumulatedContractedCost": 0,
                    "EffectiveCost": 0,
                    "ListCost": 0,
                }])
            elif MODE == "billing-missing-monetary":
                emit([{
                    "BilledCost": 0,
                    "ContractedCost": 0,
                    "CumulatedContractedCost": 0,
                    "EffectiveCost": 0,
                }])
            else:
                emit([])
        elif runtime[:3] == ["billing", "usage", "get-account-billable-metrics"]:
            emit([])
        elif runtime[:3] == ["ssl", "certificate-packs", "list"]:
            if page == 1:
                emit([{"type": "advanced" if MODE == "non-universal-cert" else "universal"}])
            else:
                emit([])
        elif runtime[:4] == ["ssl", "certificate-packs", "quota", "get"]:
            allocated = 1 if MODE == "advanced-cert-quota" else 0
            emit({"advanced": {"allocated": allocated, "used": 0}})
        elif runtime[:3] == ["zones", "settings", "get"]:
            setting = runtime[3]
            values = {
                "always_use_https": "on",
                "min_tls_version": "1.2",
                "tls_1_3": "on",
                "0rtt": "off",
                "ssl": "strict",
                "security_header": {"strict_transport_security": {"enabled": False}},
            }
            emit({"value": values[setting]})
        elif runtime[:3] == ["dns", "dnssec", "get"]:
            zone = option(runtime, "--zone")
            emit({"status": "active" if zone == ZONE_A_ID else "disabled"})
        elif runtime[:2] == ["tunnels", "list"]:
            if page == 1:
                tunnel_b_name = PRIVATE_TUNNEL_NAME if MODE == "unexpected-tunnel-name" else "lidersea-com"
                emit([
                    {"id": TUNNEL_A_ID, "name": "naranjo-online", "status": "healthy", "tun_type": "cfd_tunnel"},
                    {"id": TUNNEL_B_ID, "name": tunnel_b_name, "status": "healthy", "tun_type": "cfd_tunnel"},
                ])
            else:
                emit([])
        elif runtime[:3] == ["tunnels", "config", "get"]:
            tunnel = runtime[3]
            if tunnel == TUNNEL_A_ID:
                host, origin = "naranjo.online", "http://naranjo-online.naranjo-online.svc.cluster.local:8080"
            else:
                host, origin = "lidersea.com", "http://lidersea-com.lidersea-com.svc.cluster.local:8080"
            emit({"config": {"ingress": [{"hostname": host, "service": origin}, {"service": "http_status:404"}]}})
        elif runtime[:3] == ["tunnels", "connections", "list"]:
            tunnel = option(runtime, "--tunnel-id")
            emit([{"id": ("3" * 32 if tunnel == TUNNEL_A_ID else "4" * 32), "conns": [{"id": "live"}]}])
        elif runtime[:4] == ["network", "routes", "cidr", "list"]:
            emit([])
        elif runtime[:5] == ["zero-trust", "devices", "profiles", "custom", "list"]:
            emit([])
        elif runtime[:3] == ["dns", "records", "list"]:
            zone = option(runtime, "--zone")
            if page == 1:
                if zone == ZONE_A_ID:
                    name, tunnel = "naranjo.online", TUNNEL_A_ID
                else:
                    name, tunnel = "lidersea.com", TUNNEL_B_ID
                emit([{"name": name, "type": "CNAME", "content": tunnel + ".cfargotunnel.com", "proxied": True, "ttl": 1}])
            else:
                emit([])
        elif runtime[:3] == ["user", "tokens", "verify"]:
            emit({"id": TOKEN_ID, "status": "active"})
        elif runtime[:3] == ["user", "tokens", "get"]:
            if MODE == "denied-token-definition":
                print("token definition read denied", file=sys.stderr)
                raise SystemExit(13)
            now = datetime.now(timezone.utc)
            definition = {
                "id": OTHER_USER_ID if MODE == "token-id-mismatch" else TOKEN_ID,
                "issued_on": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "not_before": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "expires_on": (now + timedelta(minutes=25)).isoformat().replace("+00:00", "Z"),
                "value": "server-returned-secret-must-never-be-persisted-or-printed",
                "policies": [{
                    "effect": "allow",
                    "permission_groups": [
                        {"name": "Cloudflare Tunnel Read"},
                        {"name": "Zero Trust Read"},
                        {"name": "Billing Read"},
                    ],
                    "resources": {"com.cloudflare.api.account." + ACCOUNT_ID: "*"},
                }, {
                    "effect": "allow",
                    "permission_groups": [
                        {"name": "Zone Read"},
                        {"name": "Zone Settings Read"},
                        {"name": "DNS Read"},
                        {"name": "SSL and Certificates Read"},
                    ],
                    "resources": {
                        "com.cloudflare.api.account.zone." + ZONE_A_ID: "*",
                        "com.cloudflare.api.account.zone." + ZONE_B_ID: "*",
                    },
                }, {
                    "effect": "allow",
                    "permission_groups": [
                        {"name": "API Tokens Read"},
                    ],
                    "resources": {"com.cloudflare.api.user." + USER_ID: "*"},
                }],
            }
            if MODE == "token-issued-missing":
                definition.pop("issued_on")
            elif MODE == "token-issued-malformed":
                definition["issued_on"] = "not-a-timestamp"
            elif MODE == "token-issued-future":
                definition["issued_on"] = (now + timedelta(minutes=1)).isoformat()
            elif MODE == "token-issued-old":
                definition["issued_on"] = (now - timedelta(days=365)).isoformat()
            elif MODE == "token-expires-missing":
                definition.pop("expires_on")
            elif MODE == "token-expires-malformed":
                definition["expires_on"] = "not-a-timestamp"
            elif MODE == "token-expired":
                definition["issued_on"] = (now - timedelta(minutes=30)).isoformat()
                definition["expires_on"] = (now - timedelta(minutes=1)).isoformat()
            elif MODE == "token-lifetime-long":
                definition["issued_on"] = (now - timedelta(minutes=5)).isoformat()
                definition["expires_on"] = (now + timedelta(minutes=56)).isoformat()
            elif MODE == "token-not-before-future":
                definition["not_before"] = (now + timedelta(minutes=1)).isoformat()
            elif MODE == "token-not-before-malformed":
                definition["not_before"] = "not-a-timestamp"

            account_resources = definition["policies"][0]["resources"]
            zone_resources = definition["policies"][1]["resources"]
            user_resources = definition["policies"][2]["resources"]
            if MODE == "token-resource-wildcard-account":
                account_resources["com.cloudflare.api.account.*"] = account_resources.pop("com.cloudflare.api.account." + ACCOUNT_ID)
            elif MODE == "token-resource-wildcard-zone":
                zone_resources["com.cloudflare.api.account.zone.*"] = zone_resources.pop("com.cloudflare.api.account.zone." + ZONE_A_ID)
            elif MODE == "token-resource-nested":
                account_resources["com.cloudflare.api.account." + ACCOUNT_ID] = {"com.cloudflare.api.account.zone.*": "*"}
            elif MODE == "token-resource-extra-account":
                account_resources["com.cloudflare.api.account." + OTHER_ACCOUNT_ID] = "*"
            elif MODE == "token-resource-other-account":
                account_resources["com.cloudflare.api.account." + OTHER_ACCOUNT_ID] = account_resources.pop("com.cloudflare.api.account." + ACCOUNT_ID)
            elif MODE == "token-resource-extra-zone":
                zone_resources["com.cloudflare.api.account.zone." + OTHER_ZONE_ID] = "*"
            elif MODE == "token-resource-other-zone":
                zone_resources["com.cloudflare.api.account.zone." + OTHER_ZONE_ID] = zone_resources.pop("com.cloudflare.api.account.zone." + ZONE_B_ID)
            elif MODE == "token-resource-extra-user":
                user_resources["com.cloudflare.api.user." + OTHER_USER_ID] = "*"
            elif MODE == "token-resource-missing-account":
                account_resources.clear()
                account_resources["com.cloudflare.api.account.zone." + ZONE_A_ID] = "*"
            elif MODE == "token-resource-missing-zone":
                zone_resources.pop("com.cloudflare.api.account.zone." + ZONE_B_ID)
            elif MODE == "token-resource-missing-user":
                user_resources.clear()
                user_resources["com.cloudflare.api.account." + ACCOUNT_ID] = "*"
            elif MODE == "token-resource-bad-value":
                account_resources["com.cloudflare.api.account." + ACCOUNT_ID] = "read"

            if MODE == "token-policies-empty":
                definition["policies"] = []
            elif MODE == "token-policy-deny-empty":
                definition["policies"].append({"effect": "deny", "permission_groups": [], "resources": {}})
            elif MODE == "token-permission-groups-empty":
                definition["policies"][0]["permission_groups"] = []
            elif MODE == "token-write-permission":
                definition["policies"][0]["permission_groups"].append({"name": "Billing Write"})
            elif MODE == "token-extra-read-permission":
                definition["policies"][0]["permission_groups"].append({"name": "Account Settings Read"})
            emit(definition)
        else:
            raise SystemExit(9)
        """
    replacements = {
        "__MODE__": repr(mode),
        "__LOG__": repr(str(log_path)),
        "__SCHEMAS__": repr(SCHEMA_PATHS),
        "__ZONE_A_ID__": repr(ZONE_A_ID),
        "__ZONE_B_ID__": repr(ZONE_B_ID),
        "__ACCOUNT_ID__": repr(ACCOUNT_ID),
        "__TUNNEL_A_ID__": repr(TUNNEL_A_ID),
        "__TUNNEL_B_ID__": repr(TUNNEL_B_ID),
        "__TOKEN_ID__": repr(TOKEN_ID),
        "__USER_ID__": repr(USER_ID),
        "__OTHER_ACCOUNT_ID__": repr(OTHER_ACCOUNT_ID),
        "__OTHER_ZONE_ID__": repr(OTHER_ZONE_ID),
        "__OTHER_USER_ID__": repr(OTHER_USER_ID),
        "__PRIVATE_TUNNEL_NAME__": repr(PRIVATE_TUNNEL_NAME),
    }
    source = textwrap.dedent(template)
    for placeholder, value in replacements.items():
        source = source.replace(placeholder, value)
    return source


@unittest.skipUnless(BASH, "bash is unavailable")
class CloudflareAccountAuditBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.log_path = self.root / "cf.log"

    def tearDown(self):
        self.tempdir.cleanup()

    def install_fake_cf(self, mode="healthy"):
        executable = self.bin_dir / "cf"
        executable.write_text(fake_cf_source(mode, self.log_path), encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return executable

    def environment(self, extra=None):
        result = dict(os.environ)
        for name in (
            "CF_API_TOKEN",
            "CF_ACCOUNT_ID",
            "CF_ZONE_ID",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_API_KEY",
            "CLOUDFLARE_EMAIL",
            "CLOUDFLARE_API_USER_SERVICE_KEY",
            "CLOUDFLARE_ACCOUNT_ID",
            "CLOUDFLARE_ZONE_ID",
        ):
            result.pop(name, None)
        result["PATH"] = str(self.bin_dir) + os.pathsep + result["PATH"]
        if extra:
            result.update(extra)
        return result

    def run_script(self, *argv, mode="healthy", extra_env=None):
        self.install_fake_cf(mode)
        return subprocess.run(
            [required_tool(BASH, BASH_REQUIRED), str(SCRIPT), *argv],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=self.environment(extra_env),
        )

    def run_api_token_audit(self, mode="healthy"):
        return self.run_script(
            mode=mode,
            extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN},
        )

    def log_entries(self):
        if not self.log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    def assert_api_token_finding(self, mode, expected):
        completed = self.run_api_token_audit(mode)
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        self.assertIn(expected, completed.stdout)
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)

    def test_self_test_pins_version_and_all_get_schemas(self):
        completed = self.run_script("--self-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cf_version=v1.0.0-beta.5", completed.stdout)
        self.assertIn("22 operations are pinned GET requests", completed.stdout)
        self.assertIn("raw-api-absent         -> ok", completed.stdout)
        self.assertIn("failures=0", completed.stdout)

    def test_self_test_rejects_a_schema_that_becomes_mutating(self):
        completed = self.run_script("--self-test", mode="write-schema")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("cf-schema-read-only    -> FAIL", completed.stdout)

    def test_self_test_rejects_schema_body_or_path_drift(self):
        for mode in ("body-schema", "path-schema"):
            with self.subTest(mode=mode):
                completed = self.run_script("--self-test", mode=mode)
                self.assertEqual(completed.returncode, 1)
                self.assertIn("cf-schema-read-only    -> FAIL", completed.stdout)

    def test_self_test_rejects_an_unreviewed_cf_version(self):
        completed = self.run_script("--self-test", mode="old-version")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("reviewed pinned version", completed.stderr)

    def test_short_lived_api_token_completes_zero_charge_audit_without_leaking(self):
        completed = self.run_api_token_audit()
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("schema=cloudflare-account-audit/2", completed.stdout)
        self.assertIn("cf_auth=api-token-env", completed.stdout)
        self.assertIn("auth-scope the token has exactly the 8 reviewed", completed.stdout)
        self.assertIn("auth-lifetime the API token is active now", completed.stdout)
        self.assertIn("auth-resources the token is restricted to this account", completed.stdout)
        self.assertIn("account-subscriptions all 1 subscription(s)", completed.stdout)
        self.assertIn("user-subscriptions all 1 subscription(s)", completed.stdout)
        self.assertIn("billing-coverage covered=true usage_subscriptions=0", completed.stdout)
        self.assertIn("billing-usage all 0 current-period record(s)", completed.stdout)
        self.assertIn("billable-metrics complete current-period inventory count=0", completed.stdout)
        self.assertIn("billing-history all 0 item(s)", completed.stdout)
        self.assertIn("unpaid-invoices none exist", completed.stdout)
        self.assertIn("bad-debt total_debt_amount=0", completed.stdout)
        self.assertIn("certificate-packs[naranjo.online] all 1 pack(s) are Universal SSL", completed.stdout)
        self.assertIn("certificate-quota[naranjo.online] advanced allocated=0 used=0", completed.stdout)
        self.assertIn("RESULT schema=cloudflare-account-audit/2", completed.stdout)
        self.assertIn("findings=0 exit=0", completed.stdout)

        log_text = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr + log_text)
        self.assertNotIn(TOKEN_ID, completed.stdout + completed.stderr + log_text)
        self.assertNotIn(ACCOUNT_ID, completed.stdout)
        self.assertNotIn(ZONE_A_ID, completed.stdout)
        self.assertNotIn(TUNNEL_A_ID, completed.stdout)
        self.assertNotIn("server-returned-secret", completed.stdout + completed.stderr)

        entries = self.log_entries()
        self.assertTrue(any(entry["token_present"] for entry in entries))
        for entry in entries:
            self.assertNotIn(API_TOKEN, entry["args"])
        schema_entries = [entry for entry in entries if entry["args"][:1] == ["schema"]]
        self.assertTrue(schema_entries)
        self.assertTrue(all(not entry["token_present"] for entry in schema_entries))
        version_entries = [entry for entry in entries if entry["args"] == ["--version"]]
        self.assertTrue(version_entries)
        self.assertTrue(all(not entry["token_present"] for entry in version_entries))
        for command in SCHEMA_PATHS:
            with self.subTest(command=command):
                self.assertTrue(
                    any(entry["args"] == ["schema", *command] for entry in entries),
                    f"schema was not checked for {command}",
                )
                self.assertTrue(
                    any(
                        entry["token_present"]
                        and entry["args"][: len(command)] == list(command)
                        for entry in entries
                    ),
                    f"operation was not exercised for {command}",
                )

    def test_named_profile_mode_is_rejected_before_any_live_read(self):
        completed = self.run_script(
            "--profile", "audit_read", extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN}
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown argument: --profile", completed.stderr)
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)
        self.assertEqual(self.log_entries(), [])

    def test_paid_subscription_is_a_finding(self):
        self.assert_api_token_finding(
            "paid-subscription",
            "FINDING account-subscriptions 1 of 1 subscription(s)",
        )

    def test_subscription_plan_ids_use_exact_endpoint_specific_allowlists(self):
        for mode in (
            "subscription-plan-near-match",
            "subscription-plan-unknown",
            "subscription-plan-wrong-endpoint",
        ):
            with self.subTest(mode=mode):
                completed = self.run_api_token_audit(mode)
                self.assertEqual(
                    completed.returncode,
                    1,
                    completed.stderr + completed.stdout,
                )
                self.assertIn(
                    "FINDING account-subscriptions 1 of 1 subscription(s)",
                    completed.stdout,
                )
                self.assertIn(
                    "FINDING user-subscriptions 1 of 1 subscription(s)",
                    completed.stdout,
                )
                self.assertIn(
                    "FINDING zone-subscription[naranjo.online]",
                    completed.stdout,
                )

    def test_documented_uppercase_account_free_plan_id_is_allowed(self):
        completed = self.run_api_token_audit("subscription-plan-account-uppercase")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_subscription_contract_and_external_flags_fail_closed(self):
        for field in ("is_contract", "externally_managed"):
            for value in ("true", "missing"):
                with self.subTest(field=field, value=value):
                    completed = self.run_api_token_audit(
                        f"subscription-{field}-{value}"
                    )
                    self.assertEqual(
                        completed.returncode,
                        1,
                        completed.stderr + completed.stdout,
                    )
                    self.assertIn(
                        "FINDING account-subscriptions 1 of 1 subscription(s)",
                        completed.stdout,
                    )
                    self.assertIn(
                        "FINDING user-subscriptions 1 of 1 subscription(s)",
                        completed.stdout,
                    )
                    self.assertIn(
                        "FINDING zone-subscription[naranjo.online] the subscription is not a permanent zero-priced Free plan",
                        completed.stdout,
                    )
                    self.assertIn(
                        "FINDING zone-subscription[lidersea.com] the subscription is not a permanent zero-priced Free plan",
                        completed.stdout,
                    )

    def test_every_non_paid_or_missing_subscription_state_fails_closed(self):
        for state in (
            "missing",
            "Trial",
            "Provisioned",
            "AwaitingPayment",
            "Cancelled",
            "Failed",
            "Expired",
            "Unknown",
        ):
            with self.subTest(state=state):
                completed = self.run_api_token_audit(f"subscription-state-{state}")
                self.assertEqual(
                    completed.returncode,
                    1,
                    completed.stderr + completed.stdout,
                )
                self.assertIn(
                    "FINDING account-subscriptions 1 of 1 subscription(s)",
                    completed.stdout,
                )
                self.assertIn(
                    "FINDING user-subscriptions 1 of 1 subscription(s)",
                    completed.stdout,
                )
                self.assertIn(
                    "FINDING zone-subscription[naranjo.online]",
                    completed.stdout,
                )

    def test_positive_billing_history_is_a_finding(self):
        self.assert_api_token_finding(
            "positive-history",
            "FINDING billing-history nonzero_items=1 malformed_items=0 total=1",
        )

    def test_negative_billing_history_is_a_finding(self):
        self.assert_api_token_finding(
            "negative-history",
            "FINDING billing-history nonzero_items=1 malformed_items=0 total=1",
        )

    def test_nonzero_billing_cost_is_a_finding(self):
        self.assert_api_token_finding(
            "billing-cost",
            "FINDING billing-usage 1 of 1 current-period record(s)",
        )

    def test_missing_billing_monetary_field_is_a_finding(self):
        self.assert_api_token_finding(
            "billing-missing-monetary",
            "FINDING billing-usage 1 of 1 current-period record(s)",
        )

    def test_unpaid_invoice_is_a_finding(self):
        self.assert_api_token_finding(
            "unpaid-invoice",
            "FINDING unpaid-invoices count=1 nonzero=1 malformed=0",
        )

    def test_bad_debt_is_a_finding(self):
        self.assert_api_token_finding(
            "bad-debt",
            "FINDING bad-debt total_debt_amount=12.5",
        )

    def test_non_universal_certificate_is_a_finding(self):
        self.assert_api_token_finding(
            "non-universal-cert",
            "FINDING certificate-packs[naranjo.online] 1 of 1 pack(s) are non-universal",
        )

    def test_advanced_certificate_quota_is_a_finding(self):
        self.assert_api_token_finding(
            "advanced-cert-quota",
            "FINDING certificate-quota[naranjo.online] advanced allocated=1 used=0",
        )

    def test_denied_billing_endpoint_is_a_finding(self):
        self.assert_api_token_finding(
            "denied-billing",
            "FINDING billing-history the paginated invoice and payment history could not be read completely",
        )

    def test_denied_token_definition_is_a_finding(self):
        self.assert_api_token_finding(
            "denied-token-definition",
            "FINDING auth-scope the token definition could not be read; add API Tokens Read",
        )

    def test_token_identity_policy_shape_and_write_permissions_fail_closed(self):
        cases = {
            "token-id-mismatch": "FINDING auth-scope",
            "token-policies-empty": "FINDING auth-scope",
            "token-policy-deny-empty": "FINDING auth-scope",
            "token-permission-groups-empty": "FINDING auth-scope",
            "token-write-permission": "FINDING auth-scope",
            "token-extra-read-permission": "FINDING auth-scope",
        }
        for mode, expected in cases.items():
            with self.subTest(mode=mode):
                self.assert_api_token_finding(mode, expected)

    def test_old_future_expired_or_malformed_token_lifetime_fails_closed(self):
        for mode in (
            "token-issued-missing",
            "token-issued-malformed",
            "token-issued-future",
            "token-issued-old",
            "token-expires-missing",
            "token-expires-malformed",
            "token-expired",
            "token-lifetime-long",
            "token-not-before-future",
            "token-not-before-malformed",
        ):
            with self.subTest(mode=mode):
                self.assert_api_token_finding(mode, "FINDING auth-lifetime")

    def test_wildcard_nested_extra_missing_or_malformed_resources_fail_closed(self):
        for mode in (
            "token-resource-wildcard-account",
            "token-resource-wildcard-zone",
            "token-resource-nested",
            "token-resource-extra-account",
            "token-resource-extra-zone",
            "token-resource-extra-user",
            "token-resource-missing-account",
            "token-resource-missing-zone",
            "token-resource-missing-user",
            "token-resource-bad-value",
        ):
            with self.subTest(mode=mode):
                completed = self.run_api_token_audit(mode)
                self.assertEqual(
                    completed.returncode,
                    1,
                    completed.stderr + completed.stdout,
                )
                self.assertIn("FINDING auth-resources", completed.stdout)
                combined = completed.stdout + completed.stderr
                for secret in (
                    API_TOKEN,
                    ACCOUNT_ID,
                    ZONE_A_ID,
                    ZONE_B_ID,
                    USER_ID,
                    OTHER_ACCOUNT_ID,
                    OTHER_ZONE_ID,
                    OTHER_USER_ID,
                ):
                    self.assertNotIn(secret, combined)

    def test_exact_but_wrong_account_or_zone_resources_fail_after_resolution(self):
        for mode in ("token-resource-other-account", "token-resource-other-zone"):
            with self.subTest(mode=mode):
                completed = self.run_api_token_audit(mode)
                self.assertEqual(
                    completed.returncode,
                    1,
                    completed.stderr + completed.stdout,
                )
                self.assertIn(
                    "FINDING auth-resources the token resource identifiers do not exactly match",
                    completed.stdout,
                )
                self.assertNotIn(OTHER_ACCOUNT_ID, completed.stdout + completed.stderr)
                self.assertNotIn(OTHER_ZONE_ID, completed.stdout + completed.stderr)

    def test_unexpected_tunnel_name_is_counted_without_disclosure(self):
        completed = self.run_api_token_audit("unexpected-tunnel-name")
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        self.assertIn(
            "FINDING tunnel-inventory count=2 expected_present=1 unexpected=1",
            completed.stdout,
        )
        self.assertNotIn(PRIVATE_TUNNEL_NAME, completed.stdout + completed.stderr)

    def test_repeated_pagination_fails_closed(self):
        completed = self.run_api_token_audit("repeat-page")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("zone-identity", completed.stdout)
        self.assertNotIn(ACCOUNT_ID, completed.stdout)

    def test_malformed_cf_json_fails_closed(self):
        completed = self.run_api_token_audit("malformed-json")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("zone-identity", completed.stdout)

    def test_authentication_is_required_and_legacy_credentials_are_rejected(self):
        missing = self.run_script()
        self.assertEqual(missing.returncode, 2)
        self.assertIn("set a short-lived CLOUDFLARE_API_TOKEN", missing.stderr)

        legacy_secret = "legacy-secret-must-not-appear"
        legacy = self.run_script(
            extra_env={
                "CLOUDFLARE_API_TOKEN": API_TOKEN,
                "CF_API_TOKEN": legacy_secret,
            },
        )
        self.assertEqual(legacy.returncode, 2)
        self.assertIn("unset CF_API_TOKEN", legacy.stderr)
        self.assertNotIn(legacy_secret, legacy.stdout + legacy.stderr)

        malformed_token = "unsafe token value with spaces"
        malformed = self.run_script(
            extra_env={"CLOUDFLARE_API_TOKEN": malformed_token},
        )
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("CLOUDFLARE_API_TOKEN has an unsupported or unsafe format", malformed.stderr)
        self.assertNotIn(malformed_token, malformed.stdout + malformed.stderr)

    def test_raw_mode_carries_its_own_warning(self):
        completed = self.run_script(
            "--raw",
            extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("RAW MODE", completed.stdout)
        self.assertIn("Never commit it", completed.stdout)
        self.assertIn("auth token_status=active token_id=id:", completed.stdout)
        self.assertNotIn(TOKEN_ID, completed.stdout + completed.stderr)
        self.assertNotIn(
            TOKEN_ID,
            self.log_path.read_text(encoding="utf-8"),
        )


class CloudflareAccountAuditSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell_source = SCRIPT.read_text(encoding="utf-8")
        cls.reader_source = READER.read_text(encoding="utf-8")

    def test_no_raw_cloudflare_transport_or_curl_remains(self):
        combined = self.shell_source + self.reader_source
        raw_api = "api.cloudflare.com/" + "client"
        self.assertNotIn(raw_api, combined)
        self.assertNotRegex(combined, r"\bcurl\b")

    def test_every_provider_operation_is_allowlisted_at_its_reviewed_path(self):
        spec = importlib.util.spec_from_file_location("cloudflare_cf_read_contract", READER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
        operations = module.OPERATIONS
        self.assertEqual(set(operations), set(EXPECTED_OPERATIONS))
        for name, (command, api_path) in EXPECTED_OPERATIONS.items():
            with self.subTest(operation=name):
                self.assertEqual(operations[name].command, command)
                self.assertEqual(operations[name].api_path, api_path)
                self.assertNotIn(command[-1], {"create", "update", "delete", "edit"})

    def test_tunnel_inventory_keeps_the_cfd_tunnel_filter(self):
        self.assertIn('"--tun-types", "cfd_tunnel"', self.reader_source)

    def test_schema_and_live_results_are_distinguished(self):
        self.assertIn("validate_schema(cf_bin, operation, scratch)", self.reader_source)
        self.assertIn("[cf_bin, *arguments]", self.reader_source)
        self.assertIn('environment["CLOUDFLARE_API_TOKEN"] = api_token', self.reader_source)

    def test_unschematized_profile_authentication_is_absent(self):
        self.assertNotIn('"auth-whoami"', self.reader_source)
        self.assertNotIn('"auth", "whoami"', self.reader_source)
        self.assertNotIn('add_argument("--profile")', self.reader_source)
        self.assertNotIn("CF_AUTH_MODE", self.shell_source)
        self.assertNotIn("audit_profile_auth", self.shell_source)

    def test_api_token_value_is_never_interpolated_by_the_shell_or_put_in_argv(self):
        self.assertEqual(self.shell_source.count('${CLOUDFLARE_API_TOKEN:-}'), 1)
        self.assertEqual(
            self.shell_source.count('CF_API_TOKEN_VALUE="${CLOUDFLARE_API_TOKEN}"'),
            1,
        )
        self.assertIn("unset CLOUDFLARE_API_TOKEN", self.shell_source)
        self.assertIn(
            'CLOUDFLARE_API_TOKEN="${CF_API_TOKEN_VALUE}"',
            self.shell_source,
        )
        self.assertIn('value = os.environ.get("CLOUDFLARE_API_TOKEN")', self.reader_source)
        self.assertNotIn('"--api-token"', self.reader_source)

    def test_write_verbs_are_absent_from_cf_runtime_command_construction(self):
        for verb in ("create", "update", "delete", "edit"):
            with self.subTest(verb=verb):
                self.assertNotIn(f'command.append("{verb}")', self.reader_source)
                self.assertNotIn(f'command.extend(("{verb}"', self.reader_source)


class CloudflareReaderGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("cloudflare_cf_read_guards", READER)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load the Cloudflare cf adapter")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("cloudflare_cf_read_guards", None)

    def test_schema_requires_method_body_and_exact_path(self):
        operation = self.module.Operation(("zones", "list"), "/zones", "array")
        cases = (
            {"httpMethod": "POST", "path": "/zones", "hasRequestBody": False},
            {"httpMethod": "GET", "path": "/zones", "hasRequestBody": True},
            {"httpMethod": "GET", "path": "/other", "hasRequestBody": False},
        )
        for payload in cases:
            with self.subTest(payload=payload), mock.patch.object(
                self.module,
                "run_process",
                return_value=json.dumps(payload).encode("utf-8"),
            ):
                with self.assertRaises(self.module.AuditReadError):
                    self.module.validate_schema("/usr/bin/false", operation, "/tmp")

    def test_process_deadline_is_exactly_thirty_seconds(self):
        completed = subprocess.CompletedProcess(
            args=["/usr/bin/false"], returncode=0, stdout=b"{}", stderr=b""
        )
        with mock.patch.object(
            self.module.subprocess, "run", return_value=completed
        ) as run:
            self.module.run_process(
                "/usr/bin/false", ("--version",), scratch="/tmp"
            )
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_process_rejects_oversized_stdout_and_stderr(self):
        oversized = b"x" * (self.module.MAX_COMMAND_BYTES + 1)
        for stdout, stderr in ((oversized, b""), (b"{}", oversized)):
            completed = subprocess.CompletedProcess(
                args=["/usr/bin/false"], returncode=0, stdout=stdout, stderr=stderr
            )
            with self.subTest(stream="stdout" if stdout is oversized else "stderr"), \
                mock.patch.object(self.module.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(
                    self.module.AuditReadError, "5 MiB output limit"
                ):
                    self.module.run_process(
                        "/usr/bin/false", ("zones", "list"), scratch="/tmp"
                    )

    def test_paginated_collection_has_total_size_and_page_count_bounds(self):
        key = "guard-test-pages"
        operation = self.module.Operation(("zones", "list"), "/zones", "array", True)
        self.module.OPERATIONS[key] = operation
        args = Namespace(account_id=None)
        try:
            large_pages = [
                json.dumps(["a" * 3_000_000]).encode("utf-8"),
                json.dumps(["b" * 3_000_000]).encode("utf-8"),
            ]
            with mock.patch.object(self.module, "validate_schema"), mock.patch.object(
                self.module, "run_process", side_effect=large_pages
            ):
                with self.assertRaisesRegex(
                    self.module.AuditReadError, "5 MiB total limit"
                ):
                    self.module.read_operation(
                        "/usr/bin/false",
                        key,
                        args,
                        "/tmp",
                        api_token=API_TOKEN,
                    )

            def unique_page(_cf_bin, arguments, **_kwargs):
                page = arguments[arguments.index("--page") + 1]
                return json.dumps([page]).encode("utf-8")

            with mock.patch.object(self.module, "validate_schema"), mock.patch.object(
                self.module, "run_process", side_effect=unique_page
            ) as run_process:
                with self.assertRaisesRegex(
                    self.module.AuditReadError, "100-page limit"
                ):
                    self.module.read_operation(
                        "/usr/bin/false",
                        key,
                        args,
                        "/tmp",
                        api_token=API_TOKEN,
                    )
                self.assertEqual(run_process.call_count, self.module.MAX_PAGES)
        finally:
            self.module.OPERATIONS.pop(key, None)


if __name__ == "__main__":
    unittest.main()
