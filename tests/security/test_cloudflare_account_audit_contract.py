#!/usr/bin/env python3
"""Regression battery for the owner-run Cloudflare ``cf`` account audit.

``scripts/cloudflare-account-audit.sh`` needs a live API token, so no test here
supplies a real credential or reaches the network. Instead a fake ``cf`` on
``PATH`` answers the exact commands the audit's adapter
(``scripts/cloudflare_cf_read.py``) issues, and each failure mode is one fixture
mode of that fake. That exercises everything that decides whether handing the
script a token is safe and whether its verdict means anything: the credential
guard, the schema proof of the read-only command surface, pagination, the
zero-spend predicates over every zone of the account, the platform-zone
hardening checks, and the redaction that keeps a capture shareable.

``CloudflareAccountAuditBehaviourTests`` run the real script or source it and
call its real functions. ``CloudflareReaderGuardTests`` drive the adapter's
guards directly. ``CloudflareAccountAuditSourceTests`` are source-level pins,
labelled as such: they assert a rule is still written into the source, not that
it still holds against the live API.
"""

from __future__ import annotations

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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from .support import load_script, required_tool


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "cloudflare-account-audit.sh"
READER = REPO_ROOT / "scripts" / "cloudflare_cf_read.py"
BASH = shutil.which("bash")
BASH_REQUIRED = "bash is required to exercise the audit script"

ACCOUNT_ID = "c" * 32
ZONE_A_ID = "a" * 32
ZONE_B_ID = "b" * 32
ZONE_C_ID = "6" * 32
ZONE_D_ID = "7" * 32


def synthetic_uuid(character: str) -> str:
    return "-".join(character * size for size in (8, 4, 4, 4, 12))


TUNNEL_A_ID = synthetic_uuid("1")
TUNNEL_B_ID = synthetic_uuid("2")
TUNNEL_C_ID = synthetic_uuid("5")
TOKEN_ID = "d" * 32
USER_ID = "e" * 32
OTHER_ACCOUNT_ID = "f" * 32
OTHER_ZONE_ID = "9" * 32
OTHER_USER_ID = "8" * 32
# A syntactically valid but fictional classic token: 40 characters from the
# documented alphabet. It only ever reaches the fake cf.
API_TOKEN = "fixture_read_only_token_".ljust(40, "x")
PRIVATE_TUNNEL_NAME = "private-customer-tunnel-do-not-print"
PRIVATE_ZONE_NAME = "private-zone-do-not-print.example"

PLATFORM_ZONES = {
    "naranjo.online": (ZONE_A_ID, TUNNEL_A_ID, "naranjo-online", "active"),
    "lidersea.com": (ZONE_B_ID, TUNNEL_B_ID, "lidersea-com", "active"),
    "hospedajedonlolo.com": (ZONE_C_ID, TUNNEL_C_ID, "hospedajedonlolo-com", "active"),
}
UNSERVED_ZONE = "sloptube.fun"

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
    "hostname-routes": (
        ("network", "routes", "hostname", "list"),
        "/accounts/{account_id}/zerotrust/routes/hostname",
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
# Commands that describe what the platform serves. They must never be issued
# for a zone the platform does not serve.
PLATFORM_ONLY_COMMANDS = (
    ("zones", "settings", "get"),
    ("dns", "dnssec", "get"),
    ("dns", "records", "list"),
)


def fake_cf_source(mode: str, log_path: Path) -> str:
    template = """\
        from datetime import datetime, timedelta, timezone
        import json
        import os
        import sys

        MODE = __MODE__
        LOG = __LOG__
        PLATFORM_ZONES = __PLATFORM_ZONES__
        UNSERVED_ZONE = __UNSERVED_ZONE__
        ZONE_A_ID = __ZONE_A_ID__
        ZONE_B_ID = __ZONE_B_ID__
        ZONE_C_ID = __ZONE_C_ID__
        ZONE_D_ID = __ZONE_D_ID__
        ACCOUNT_ID = __ACCOUNT_ID__
        TOKEN_ID = __TOKEN_ID__
        USER_ID = __USER_ID__
        OTHER_ACCOUNT_ID = __OTHER_ACCOUNT_ID__
        OTHER_ZONE_ID = __OTHER_ZONE_ID__
        OTHER_USER_ID = __OTHER_USER_ID__
        PRIVATE_TUNNEL_NAME = __PRIVATE_TUNNEL_NAME__
        PRIVATE_ZONE_NAME = __PRIVATE_ZONE_NAME__
        ACCOUNT_KEY = "com.cloudflare.api.account." + ACCOUNT_ID
        OTHER_ACCOUNT_KEY = "com.cloudflare.api.account." + OTHER_ACCOUNT_ID
        ALL_ZONES = {"com.cloudflare.api.account.zone.*": "*"}

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
            if MODE == "component-priced":
                result["component_values"] = [
                    {"name": "page_rules", "value": 5, "default": 3, "price": 5}
                ]
            elif MODE == "component-price-missing":
                result["component_values"] = [
                    {"name": "page_rules", "value": 3, "default": 3}
                ]
            elif MODE == "component-free":
                result["component_values"] = [
                    {"name": "page_rules", "value": 3, "default": 3, "price": 0}
                ]
            return result

        def zone(zone_id, name, plan="Free Website", account=ACCOUNT_ID):
            return {
                "id": zone_id,
                "name": name,
                "account": {"id": account},
                "plan": {"name": plan},
                "status": "active",
            }

        def zone_pages():
            first = [zone(ZONE_A_ID, "naranjo.online"), zone(ZONE_B_ID, "lidersea.com")]
            second = [zone(ZONE_C_ID, "hospedajedonlolo.com")]
            if MODE == "unserved-zone-paid":
                second.append(zone(ZONE_D_ID, UNSERVED_ZONE, plan="Pro Website"))
            elif MODE != "unserved-zone-absent":
                second.append(zone(ZONE_D_ID, UNSERVED_ZONE))
            if MODE == "unexpected-paid-zone":
                second.append(zone(OTHER_ZONE_ID, PRIVATE_ZONE_NAME, plan="Pro Website"))
            elif MODE == "platform-zone-missing":
                second = [item for item in second if item["id"] != ZONE_C_ID]
            elif MODE == "zone-foreign-account":
                second[0] = zone(ZONE_C_ID, "hospedajedonlolo.com", account=OTHER_ACCOUNT_ID)
            elif MODE == "zone-duplicate-name":
                second.append(zone(OTHER_ZONE_ID, "naranjo.online"))
            elif MODE == "zone-malformed":
                second.append({"id": "not-a-zone-id", "name": "x.example", "account": {"id": ACCOUNT_ID}})
            return [first, second]

        def zone_name_for(zone_id):
            for item in zone_pages()[0] + zone_pages()[1]:
                if item["id"] == zone_id:
                    return item["name"]
            return None

        args = sys.argv[1:]
        logged_args = ["<token-id>" if item == TOKEN_ID else item for item in args]
        with open(LOG, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "args": logged_args,
                "account": os.environ.get("CLOUDFLARE_ACCOUNT_ID"),
                "token_present": bool(os.environ.get("CLOUDFLARE_API_TOKEN")),
                "cwd": os.getcwd(),
                "delegation": os.environ.get("CF_DELEGATION"),
            }) + "\\n")

        runtime = list(args)
        page = int(option(runtime, "--page", "1"))

        if runtime[:2] == ["zones", "list"]:
            # The fake ignores the --account-id filter on purpose: it models a
            # CLI that drops the filter, which the audit must still catch.
            pages = zone_pages()
            if MODE == "malformed-json":
                print("not-json")
            elif MODE == "repeat-page":
                emit(pages[0])
            elif page <= len(pages):
                emit(pages[page - 1])
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
            if MODE == "unserved-zone-paid" and option(runtime, "--zone") == ZONE_D_ID:
                emit({"price": 20, "rate_plan": {"id": "pro", "is_contract": False, "externally_managed": False}, "state": "Paid"})
            else:
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
            zone_id = option(runtime, "--zone")
            advanced = (
                (MODE == "non-universal-cert" and zone_id == ZONE_A_ID)
                or (MODE == "unserved-zone-advanced-cert" and zone_id == ZONE_D_ID)
            )
            if page == 1:
                emit([{"type": "advanced" if advanced else "universal"}])
            else:
                emit([])
        elif runtime[:4] == ["ssl", "certificate-packs", "quota", "get"]:
            allocated = 1 if MODE == "advanced-cert-quota" else 0
            emit({"advanced": {"allocated": allocated, "used": 0}})
        elif runtime[:3] == ["zones", "settings", "get"]:
            if option(runtime, "--zone") not in {ZONE_A_ID, ZONE_B_ID, ZONE_C_ID}:
                raise SystemExit(11)
            setting = runtime[3]
            values = {
                "always_use_https": "on",
                "min_tls_version": "1.2",
                "tls_1_3": "on",
                "0rtt": "off",
                "ssl": "strict",
                "security_header": {"strict_transport_security": {"enabled": False}},
            }
            if MODE == "platform-zone-c-unhardened" and option(runtime, "--zone") == ZONE_C_ID:
                values["min_tls_version"] = "1.0"
            emit({"value": values[setting]})
        elif runtime[:3] == ["dns", "dnssec", "get"]:
            name = zone_name_for(option(runtime, "--zone"))
            if name not in PLATFORM_ZONES:
                raise SystemExit(11)
            emit({"status": PLATFORM_ZONES[name][3]})
        elif runtime[:2] == ["tunnels", "list"]:
            if page == 1:
                tunnel_b_name = "lidersea-com"
                if MODE == "unexpected-tunnel-name":
                    tunnel_b_name = PRIVATE_TUNNEL_NAME
                elif MODE == "duplicate-tunnel-name":
                    tunnel_b_name = "naranjo-online"
                emit([
                    {"id": PLATFORM_ZONES["naranjo.online"][1], "name": "naranjo-online", "status": "healthy", "tun_type": "cfd_tunnel"},
                    {"id": PLATFORM_ZONES["lidersea.com"][1], "name": tunnel_b_name, "status": "healthy", "tun_type": "cfd_tunnel"},
                    {"id": PLATFORM_ZONES["hospedajedonlolo.com"][1], "name": "hospedajedonlolo-com", "status": "healthy", "tun_type": "cfd_tunnel"},
                ])
            else:
                emit([])
        elif runtime[:3] == ["tunnels", "config", "get"]:
            tunnel = runtime[3]
            for host, (_zone_id, tunnel_id, tunnel_name, _dnssec) in PLATFORM_ZONES.items():
                if tunnel == tunnel_id:
                    origin = "http://{0}.{0}.svc.cluster.local:8080".format(tunnel_name)
                    emit({"config": {"ingress": [{"hostname": host, "service": origin}, {"service": "http_status:404"}]}})
                    break
            else:
                raise SystemExit(12)
        elif runtime[:3] == ["tunnels", "connections", "list"]:
            tunnel = option(runtime, "--tunnel-id")
            emit([{"id": tunnel.replace("-", "")[:32], "conns": [{"id": "live"}]}])
        elif runtime[:4] == ["network", "routes", "cidr", "list"]:
            # A live route is listed unless the request asks for deleted ones.
            if MODE == "private-route" and page == 1 and option(runtime, "--is-deleted") != "true":
                emit([{"id": "route", "network": "198.51.100.0/24"}])
            else:
                emit([])
        elif runtime[:4] == ["network", "routes", "hostname", "list"]:
            if MODE == "hostname-route" and page == 1 and option(runtime, "--is-deleted") != "true":
                emit([{"id": "route", "hostname": "private.example"}])
            else:
                emit([])
        elif runtime[:5] == ["zero-trust", "devices", "profiles", "custom", "list"]:
            emit([])
        elif runtime[:3] == ["dns", "records", "list"]:
            name = zone_name_for(option(runtime, "--zone"))
            if name not in PLATFORM_ZONES:
                raise SystemExit(11)
            tunnel = PLATFORM_ZONES[name][1]
            if page == 1:
                emit([{"name": name, "type": "CNAME", "content": tunnel + ".cfargotunnel.com", "proxied": True, "ttl": 1}])
            elif page == 2 and MODE == "dns-second-page-address" and name == "naranjo.online":
                emit([{"name": "origin." + name, "type": "A", "content": "192.0.2.1", "proxied": False, "ttl": 1}])
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
                    "resources": {ACCOUNT_KEY: "*"},
                }, {
                    "effect": "allow",
                    "permission_groups": [
                        {"name": "Zone Read"},
                        {"name": "Zone Settings Read"},
                        {"name": "DNS Read"},
                        {"name": "SSL and Certificates Read"},
                    ],
                    "resources": {ACCOUNT_KEY: dict(ALL_ZONES)},
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

            account_policy = definition["policies"][0]
            zone_policy = definition["policies"][1]
            user_policy = definition["policies"][2]
            named_zones = {
                "com.cloudflare.api.account.zone." + zone_id: "*"
                for zone_id in (ZONE_A_ID, ZONE_B_ID, ZONE_C_ID, ZONE_D_ID)
            }
            if MODE == "token-resource-wildcard-account":
                account_policy["resources"] = {"com.cloudflare.api.account.*": "*"}
            elif MODE == "token-resource-global-zone-wildcard":
                zone_policy["resources"] = {"com.cloudflare.api.account.zone.*": "*"}
            elif MODE == "token-resource-named-zones":
                zone_policy["resources"] = named_zones
            elif MODE == "token-resource-nested-named-zone":
                zone_policy["resources"] = {ACCOUNT_KEY: {"com.cloudflare.api.account.zone." + ZONE_A_ID: "*"}}
            elif MODE == "token-resource-nested-extra":
                zone_policy["resources"][ACCOUNT_KEY]["com.cloudflare.api.account.zone." + OTHER_ZONE_ID] = "*"
            elif MODE == "token-resource-nested-value":
                zone_policy["resources"] = {ACCOUNT_KEY: {"com.cloudflare.api.account.zone.*": "read"}}
            elif MODE == "token-resource-nested":
                account_policy["resources"] = {ACCOUNT_KEY: dict(ALL_ZONES)}
            elif MODE == "token-resource-extra-account":
                account_policy["resources"][OTHER_ACCOUNT_KEY] = "*"
            elif MODE == "token-resource-zones-other-account":
                zone_policy["resources"] = {OTHER_ACCOUNT_KEY: dict(ALL_ZONES)}
            elif MODE == "token-resource-extra-user":
                user_policy["resources"]["com.cloudflare.api.user." + OTHER_USER_ID] = "*"
            elif MODE == "token-resource-user-nested":
                user_policy["resources"] = {"com.cloudflare.api.user." + USER_ID: dict(ALL_ZONES)}
            elif MODE == "token-resource-missing-account":
                account_policy["resources"] = {"com.cloudflare.api.user." + USER_ID: "*"}
            elif MODE == "token-resource-missing-zones":
                zone_policy["resources"] = {ACCOUNT_KEY: "*"}
            elif MODE == "token-resource-missing-user":
                user_policy["resources"] = {ACCOUNT_KEY: "*"}
            elif MODE == "token-resource-bad-value":
                account_policy["resources"][ACCOUNT_KEY] = "read"
            elif MODE == "token-resource-other-account":
                account_policy["resources"] = {OTHER_ACCOUNT_KEY: "*"}
                zone_policy["resources"] = {OTHER_ACCOUNT_KEY: dict(ALL_ZONES)}

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
            elif MODE == "token-swapped-read-permission":
                # Same count, all Read, one group swapped: only the exact set catches it.
                definition["policies"][0]["permission_groups"][1] = {"name": "Account Settings Read"}
            emit(definition)
        else:
            raise SystemExit(9)
        """
    replacements = {
        "__MODE__": repr(mode),
        "__LOG__": repr(str(log_path)),
        "__PLATFORM_ZONES__": repr(PLATFORM_ZONES),
        "__UNSERVED_ZONE__": repr(UNSERVED_ZONE),
        "__ZONE_A_ID__": repr(ZONE_A_ID),
        "__ZONE_B_ID__": repr(ZONE_B_ID),
        "__ZONE_C_ID__": repr(ZONE_C_ID),
        "__ZONE_D_ID__": repr(ZONE_D_ID),
        "__ACCOUNT_ID__": repr(ACCOUNT_ID),
        "__TOKEN_ID__": repr(TOKEN_ID),
        "__USER_ID__": repr(USER_ID),
        "__OTHER_ACCOUNT_ID__": repr(OTHER_ACCOUNT_ID),
        "__OTHER_ZONE_ID__": repr(OTHER_ZONE_ID),
        "__OTHER_USER_ID__": repr(OTHER_USER_ID),
        "__PRIVATE_TUNNEL_NAME__": repr(PRIVATE_TUNNEL_NAME),
        "__PRIVATE_ZONE_NAME__": repr(PRIVATE_ZONE_NAME),
    }
    source = textwrap.dedent(template)
    for placeholder, value in replacements.items():
        source = source.replace(placeholder, value)
    return source


def fake_cf_front_source(mode: str, log_path: Path, python_fake: Path) -> str:
    """The fake ``cf`` executable: a POSIX-sh front for ``--version`` and
    ``cf schema``, the two metadata calls the adapter makes before every read.

    Answering them without a Python start roughly halves the cost of one
    audit run; every other call is handed to the Python fake unchanged. The
    log line has the Python fake's exact shape, so tests read one log.
    """

    def quote(value: str) -> str:
        return "'" + value.replace("'", "'\\''") + "'"

    schema_cases = "\n".join(
        "  {}) path={} ;;".format(quote(" ".join(command)), quote(path))
        for command, path in SCHEMA_PATHS.items()
    )
    return textwrap.dedent("""\
        #!/bin/sh
        case "${{1:-}}" in
          --version|schema) ;;
          *) exec {python} -IS {python_fake} "$@" ;;
        esac
        mode={mode}
        token=false
        [ -n "${{CLOUDFLARE_API_TOKEN:-}}" ] && token=true
        account=null
        [ -n "${{CLOUDFLARE_ACCOUNT_ID:-}}" ] && account="\\"$CLOUDFLARE_ACCOUNT_ID\\""
        args=
        for item in "$@"; do args="${{args:+$args, }}\\"$item\\""; done
        printf '{{"args": [%s], "account": %s, "token_present": %s, "cwd": "%s", "delegation": "%s"}}\\n' \\
          "$args" "$account" "$token" "$PWD" "${{CF_DELEGATION:-}}" >>{log}
        if [ "$1" = --version ]; then
          if [ "$mode" = old-version ]; then echo 'cf v1.0.0-beta.4'; else echo 'cf v1.0.0-beta.5'; fi
          exit 0
        fi
        shift
        case "$*" in
        {schema_cases}
          *) exit 7 ;;
        esac
        method=GET
        body=false
        if [ "$*" = 'zones list' ]; then
          case "$mode" in
            write-schema) method=POST; body=true ;;
            path-schema) path=/unexpected ;;
            body-schema) body=true ;;
          esac
        fi
        printf '{{"httpMethod": "%s", "path": "%s", "hasRequestBody": %s}}\\n' \\
          "$method" "$path" "$body"
        """).format(
        python=quote(sys.executable),
        python_fake=quote(str(python_fake)),
        mode=quote(mode),
        log=quote(str(log_path)),
        schema_cases=schema_cases,
    )


# Independent fixture modes run concurrently: each audit is a few hundred short
# processes, so a table of modes run one after another dominates the battery.
PARALLEL_RUNS = max(1, min(4, os.cpu_count() or 1))


def write_fake_cf(root: Path, mode: str) -> Path:
    """Install the fake cf for one mode under ``root/bin``; return its log."""

    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    log_path = root / "cf.log"
    python_fake = root / "fake_cf.py"
    python_fake.write_text(fake_cf_source(mode, log_path), encoding="utf-8")
    executable = bin_dir / "cf"
    executable.write_text(
        fake_cf_front_source(mode, log_path, python_fake), encoding="utf-8"
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return log_path


def read_log(log_path: Path) -> list:
    if not log_path.exists():
        return []
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


def calls_for(entries, command, identifier):
    return [
        entry
        for entry in entries
        if entry["args"][: len(command)] == list(command)
        and identifier in entry["args"]
    ]


@unittest.skipUnless(BASH, "bash is unavailable")
class CloudflareAccountAuditBehaviourTests(unittest.TestCase):
    """Behavioural: the real script against a fake cf, with no network."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.bin_dir = self.root / "bin"
        self.log_path = self.root / "cf.log"

    def tearDown(self):
        self.tempdir.cleanup()

    def install_fake_cf(self, mode="healthy"):
        write_fake_cf(self.root, mode)

    def environment(self, extra=None, bin_dir=None):
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
        result["PATH"] = str(bin_dir or self.bin_dir) + os.pathsep + result["PATH"]
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

    def call_function(self, program):
        """Source the script and run shell code against its real functions."""

        self.install_fake_cf()
        return subprocess.run(
            [
                required_tool(BASH, BASH_REQUIRED),
                "-c",
                ". '{}'\n{}\n".format(SCRIPT, program),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            env=self.environment(),
        )

    def run_api_token_audit(self, mode="healthy"):
        return self.run_script(
            mode=mode,
            extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN},
        )

    def run_modes(self, modes):
        """Run one token audit per mode, concurrently, each with its own fake
        cf and log. Returns ``{mode: (completed, log entries)}``."""

        def one(mode):
            root = self.root / ("mode-" + mode)
            log_path = write_fake_cf(root, mode)
            completed = subprocess.run(
                [required_tool(BASH, BASH_REQUIRED), str(SCRIPT)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=self.environment(
                    {"CLOUDFLARE_API_TOKEN": API_TOKEN}, bin_dir=root / "bin"
                ),
            )
            return mode, (completed, read_log(log_path))

        with ThreadPoolExecutor(max_workers=PARALLEL_RUNS) as pool:
            return dict(pool.map(one, list(modes)))

    def assert_findings(self, cases):
        """``cases`` maps a fixture mode to the finding line(s) it must print.
        Every mode must exit 1 and keep the token out of its output."""

        runs = self.run_modes(cases)
        for mode, expected in cases.items():
            completed = runs[mode][0]
            with self.subTest(mode=mode):
                self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
                for text in (expected,) if isinstance(expected, str) else expected:
                    self.assertIn(text, completed.stdout)
                self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)
        return runs

    def assert_api_token_finding(self, mode, expected):
        """One mode in this test's own directory, so ``log_entries`` reads it."""

        completed = self.run_api_token_audit(mode)
        self.assertEqual(completed.returncode, 1, completed.stderr + completed.stdout)
        self.assertIn(expected, completed.stdout)
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)
        return completed

    def log_entries(self):
        return read_log(self.log_path)

    def assert_every_cf_call_isolated(self):
        # A launcher started in the caller's directory, or with hand-off on,
        # could run a project-local cf before the pin is checked (#402 review).
        entries = self.log_entries()
        self.assertTrue(entries)
        for entry in entries:
            with self.subTest(args=entry["args"]):
                self.assertEqual(entry["delegation"], "1")
                self.assertFalse(Path(entry["cwd"]).resolve().is_relative_to(REPO_ROOT.resolve()), entry["cwd"])

    def provider_calls(self, command, zone_id):
        return calls_for(self.log_entries(), command, zone_id)

    def test_self_test_pins_version_and_all_get_schemas(self):
        completed = self.run_script("--self-test")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cf_version=v1.0.0-beta.5", completed.stdout)
        self.assertIn("23 operations are pinned GET requests", completed.stdout)
        self.assertIn("raw-api-absent         -> ok", completed.stdout)
        self.assertIn("credential-untouched   -> ok", completed.stdout)
        self.assertIn("failures=0", completed.stdout)
        self.assert_every_cf_call_isolated()

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

    def test_a_drifted_schema_stops_a_live_audit_before_any_credentialed_read(self):
        completed = self.run_api_token_audit("write-schema")
        self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
        self.assertIn("read-only command surface", completed.stderr)
        self.assertFalse(any(entry["token_present"] for entry in self.log_entries()))

    def test_help_states_the_credential_and_redaction_contract(self):
        completed = self.run_script("--help")
        self.assertEqual(completed.returncode, 0)
        self.assertIn("CLOUDFLARE_API_TOKEN", completed.stdout)
        self.assertIn("READ-ONLY", completed.stdout)
        self.assertIn("Never pass a token as an argument", completed.stdout)
        self.assertIn("--raw", completed.stdout)
        self.assertEqual(self.log_entries(), [])

    def test_short_lived_api_token_completes_zero_charge_audit_without_leaking(self):
        completed = self.run_api_token_audit()
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        for expected in (
            "schema=cloudflare-account-audit/2",
            "cf_auth=api-token-env",
            "auth-scope the token has exactly the 8 reviewed",
            "auth-lifetime the API token is active now",
            "auth-resources the token is restricted to one account",
            "zone-inventory count=4 ",
            "zone-allowlist every zone is one ADR 0006 allows",
            "sloptube.fun present=yes",
            "account-subscriptions all 1 subscription(s)",
            "user-subscriptions all 1 subscription(s)",
            "billing-coverage covered=true usage_subscriptions=0",
            "billing-usage all 0 current-period record(s)",
            "billable-metrics complete current-period inventory count=0",
            "billing-history all 0 item(s)",
            "unpaid-invoices none exist",
            "bad-debt total_debt_amount=0",
            "tunnel-inventory exactly the three expected per-site Tunnels exist",
            "hostname-routes none exist",
            "RESULT schema=cloudflare-account-audit/2",
            "findings=0 exit=0",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, completed.stdout)

        # Zero spend covers every zone the account lists, served or not.
        for zone_name in (*PLATFORM_ZONES, UNSERVED_ZONE):
            for check in (
                f"OK zone-plan[{zone_name}] plan=Free Website status=active",
                f"OK zone-subscription[{zone_name}] permanent Free plan price=0",
                f"OK certificate-packs[{zone_name}] all 1 pack(s) are Universal SSL",
                f"OK certificate-quota[{zone_name}] advanced allocated=0 used=0",
            ):
                with self.subTest(check=check):
                    self.assertIn(check, completed.stdout)
        # Hardening, DNSSEC, Tunnel and DNS checks cover the platform zones,
        # and only them: the unserved zone is never read for them.
        for zone_name, (zone_id, _tunnel, tunnel_name, dnssec) in PLATFORM_ZONES.items():
            for check in (
                f"OK zone-setting[{zone_name}/min_tls_version] value=1.2",
                f"OK zone-setting[{zone_name}/managed-hsts] enabled=false",
                f"OK zone-dnssec[{zone_name}] status={dnssec}",
                f"OK tunnel[{tunnel_name}] ingress is exactly one {zone_name} rule",
                f"OK zone-dns[{zone_name}] exactly one proxied apex CNAME",
            ):
                with self.subTest(check=check):
                    self.assertIn(check, completed.stdout)
        for command in PLATFORM_ONLY_COMMANDS:
            with self.subTest(unserved=command):
                self.assertEqual(self.provider_calls(command, ZONE_D_ID), [])
                self.assertTrue(self.provider_calls(command, ZONE_C_ID))
        self.assertNotIn(f"[{UNSERVED_ZONE}/", completed.stdout)
        self.assertNotIn(f"zone-dns[{UNSERVED_ZONE}]", completed.stdout)

        log_text = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr + log_text)
        self.assertNotIn(TOKEN_ID, completed.stdout + completed.stderr + log_text)
        for identifier in (ACCOUNT_ID, ZONE_A_ID, ZONE_C_ID, ZONE_D_ID, TUNNEL_A_ID, USER_ID):
            self.assertNotIn(identifier, completed.stdout)
        self.assertNotIn("server-returned-secret", completed.stdout + completed.stderr)

        self.assert_every_cf_call_isolated()
        entries = self.log_entries()
        self.assertTrue(any(entry["token_present"] for entry in entries))
        for entry in entries:
            self.assertNotIn(API_TOKEN, entry["args"])
        zone_lists = [entry for entry in entries if entry["args"][:2] == ["zones", "list"]]
        self.assertTrue(zone_lists)
        for entry in zone_lists:
            self.assertEqual(entry["args"][2:4], ["--account-id", ACCOUNT_ID])
        # Pagination ran to the empty page: two zone pages, then the stop page.
        self.assertEqual(sorted({entry["args"][-1] for entry in zone_lists}), ["1", "2", "3"])
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

    def test_unserved_zone_is_allowed_but_not_required(self):
        completed = self.run_api_token_audit("unserved-zone-absent")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("zone-inventory count=3 ", completed.stdout)
        self.assertIn("sloptube.fun present=no", completed.stdout)

    def test_unserved_zone_gets_every_zero_spend_check(self):
        cases = {
            "unserved-zone-paid": (
                "FINDING zone-plan[sloptube.fun] plan=Pro Website status=active",
                "FINDING zone-subscription[sloptube.fun] the subscription is not a permanent zero-priced Free plan",
            ),
            "unserved-zone-advanced-cert": (
                "FINDING certificate-packs[sloptube.fun] 1 of 1 pack(s) are non-universal",
            ),
        }
        runs = self.assert_findings(cases)
        for mode, (completed, _entries) in runs.items():
            with self.subTest(mode=mode):
                self.assertNotIn("FINDING zone-plan[naranjo.online]", completed.stdout)

    def test_a_zone_outside_the_allowed_set_is_a_finding_and_still_audited_for_spend(self):
        completed = self.assert_api_token_finding(
            "unexpected-paid-zone",
            "FINDING zone-allowlist 1 zone(s) outside ADR 0006's allowed set: id:",
        )
        self.assertIn("zone-inventory count=5 ", completed.stdout)
        self.assertRegex(completed.stdout, r"FINDING zone-plan\[id:[0-9a-f]{12}\] plan=Pro Website")
        self.assertRegex(completed.stdout, r"OK zone-subscription\[id:[0-9a-f]{12}\]")
        self.assertRegex(completed.stdout, r"OK certificate-packs\[id:[0-9a-f]{12}\]")
        self.assertNotIn(PRIVATE_ZONE_NAME, completed.stdout + completed.stderr)
        self.assertNotIn(OTHER_ZONE_ID, completed.stdout + completed.stderr)
        for command in PLATFORM_ONLY_COMMANDS:
            with self.subTest(command=command):
                self.assertEqual(self.provider_calls(command, OTHER_ZONE_ID), [])

    def test_unsound_zone_inventories_stop_the_audit(self):
        cases = {
            "platform-zone-missing": "FINDING zone-inventory platform zone(s) missing: hospedajedonlolo.com;",
            "zone-foreign-account": "FINDING zone-inventory 1 of 4 zone(s) belong to another account",
            "zone-duplicate-name": "FINDING zone-inventory 1 zone name(s) appear more than once",
            "zone-malformed": "FINDING zone-inventory 1 of 5 zone record(s) lack a well-formed",
            "repeat-page": "FINDING zone-inventory the account zone inventory could not be read completely",
            "malformed-json": "FINDING zone-inventory the account zone inventory could not be read completely",
        }
        for mode, (completed, _entries) in self.assert_findings(cases).items():
            with self.subTest(mode=mode):
                self.assertNotIn("## zero spend", completed.stdout)
                self.assertIn("exit=1", completed.stdout)
                self.assertNotIn(ACCOUNT_ID, completed.stdout)
                self.assertNotIn(OTHER_ACCOUNT_ID, completed.stdout)

    def test_named_profile_mode_is_rejected_before_any_live_read(self):
        completed = self.run_script(
            "--profile", "audit_read", extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN}
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown argument: --profile", completed.stderr)
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)
        self.assertEqual(self.log_entries(), [])

    def test_a_token_shaped_argument_is_refused(self):
        # The one mistake that would put a bearer in the process table.
        completed = self.run_script(API_TOKEN)
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(API_TOKEN, completed.stdout + completed.stderr)
        self.assertIn("unknown argument", completed.stderr)
        self.assertEqual(self.log_entries(), [])

    def test_subscription_plan_ids_use_exact_endpoint_specific_allowlists(self):
        expected = (
            "FINDING account-subscriptions 1 of 1 subscription(s)",
            "FINDING user-subscriptions 1 of 1 subscription(s)",
            "FINDING zone-subscription[naranjo.online]",
        )
        self.assert_findings({
            mode: expected
            for mode in (
                "subscription-plan-near-match",
                "subscription-plan-unknown",
                "subscription-plan-wrong-endpoint",
            )
        })

    def test_documented_uppercase_account_free_plan_id_is_allowed(self):
        completed = self.run_api_token_audit("subscription-plan-account-uppercase")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_subscription_contract_and_external_flags_fail_closed(self):
        expected = (
            "FINDING account-subscriptions 1 of 1 subscription(s)",
            "FINDING user-subscriptions 1 of 1 subscription(s)",
            *(
                f"FINDING zone-subscription[{zone_name}] the subscription is not a permanent zero-priced Free plan"
                for zone_name in (*PLATFORM_ZONES, UNSERVED_ZONE)
            ),
        )
        self.assert_findings({
            f"subscription-{field}-{value}": expected
            for field in ("is_contract", "externally_managed")
            for value in ("true", "missing")
        })

    def test_every_non_paid_or_missing_subscription_state_fails_closed(self):
        expected = (
            "FINDING account-subscriptions 1 of 1 subscription(s)",
            "FINDING user-subscriptions 1 of 1 subscription(s)",
            "FINDING zone-subscription[naranjo.online]",
        )
        self.assert_findings({
            f"subscription-state-{state}": expected
            for state in (
                "missing",
                "Trial",
                "Provisioned",
                "AwaitingPayment",
                "Cancelled",
                "Failed",
                "Expired",
                "Unknown",
            )
        })

    def test_priced_or_unpriced_subscription_components_fail_closed(self):
        expected = (
            "FINDING account-subscriptions 1 of 1 subscription(s)",
            "FINDING user-subscriptions 1 of 1 subscription(s)",
            *(f"FINDING zone-subscription[{zone_name}]" for zone_name in (*PLATFORM_ZONES, UNSERVED_ZONE)),
        )
        self.assert_findings({
            mode: expected for mode in ("component-priced", "component-price-missing")
        })

    def test_zero_priced_components_are_allowed(self):
        # The vacuity probe for the test above: a component rule that refused
        # every component would also satisfy it.
        completed = self.run_api_token_audit("component-free")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_each_charge_or_unreadable_billing_answer_is_a_finding(self):
        self.assert_findings({
            "paid-subscription": "FINDING account-subscriptions 1 of 1 subscription(s)",
            "positive-history": "FINDING billing-history nonzero_items=1 malformed_items=0 total=1",
            "negative-history": "FINDING billing-history nonzero_items=1 malformed_items=0 total=1",
            "billing-cost": "FINDING billing-usage 1 of 1 current-period record(s)",
            "billing-missing-monetary": "FINDING billing-usage 1 of 1 current-period record(s)",
            "unpaid-invoice": "FINDING unpaid-invoices count=1 nonzero=1 malformed=0",
            "bad-debt": "FINDING bad-debt total_debt_amount=12.5",
            "non-universal-cert": "FINDING certificate-packs[naranjo.online] 1 of 1 pack(s) are non-universal",
            "advanced-cert-quota": "FINDING certificate-quota[naranjo.online] advanced allocated=1 used=0",
            "denied-billing": "FINDING billing-history the paginated invoice and payment history could not be read completely",
            "denied-token-definition": "FINDING auth-scope the token definition could not be read; add API Tokens Read",
        })

    def test_token_identity_policy_shape_and_write_permissions_fail_closed(self):
        cases = {
            "token-id-mismatch": "FINDING auth-scope",
            "token-policies-empty": "FINDING auth-scope",
            "token-policy-deny-empty": "FINDING auth-scope",
            "token-permission-groups-empty": "FINDING auth-scope",
            "token-write-permission": "FINDING auth-scope",
            "token-extra-read-permission": "FINDING auth-scope",
            "token-swapped-read-permission": "FINDING auth-scope",
        }
        self.assert_findings(cases)

    def test_old_future_expired_or_malformed_token_lifetime_fails_closed(self):
        self.assert_findings({
            mode: "FINDING auth-lifetime"
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
            )
        })

    def test_token_resources_must_be_one_account_its_zones_and_one_user(self):
        runs = self.assert_findings({
            mode: "FINDING auth-resources"
            for mode in (
                "token-resource-wildcard-account",
                "token-resource-global-zone-wildcard",
                "token-resource-named-zones",
                "token-resource-nested-named-zone",
                "token-resource-nested-extra",
                "token-resource-nested-value",
                "token-resource-nested",
                "token-resource-extra-account",
                "token-resource-zones-other-account",
                "token-resource-extra-user",
                "token-resource-user-nested",
                "token-resource-missing-account",
                "token-resource-missing-zones",
                "token-resource-missing-user",
                "token-resource-bad-value",
            )
        })
        for mode, (completed, entries) in runs.items():
            with self.subTest(mode=mode):
                self.assertNotIn("## zones", completed.stdout)
                self.assertFalse(
                    any(entry["args"][:2] == ["zones", "list"] for entry in entries)
                )
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

    def test_the_token_account_binds_the_zone_inventory(self):
        completed = self.assert_api_token_finding(
            "token-resource-other-account",
            "FINDING zone-inventory 4 of 4 zone(s) belong to another account than the token's",
        )
        self.assertIn("OK auth-resources", completed.stdout)
        zone_lists = [e for e in self.log_entries() if e["args"][:2] == ["zones", "list"]]
        self.assertTrue(zone_lists)
        self.assertTrue(all(e["args"][2:4] == ["--account-id", OTHER_ACCOUNT_ID] for e in zone_lists))
        self.assertNotIn(OTHER_ACCOUNT_ID, completed.stdout + completed.stderr)

    def test_unexpected_tunnel_name_is_counted_without_disclosure(self):
        completed = self.assert_api_token_finding(
            "unexpected-tunnel-name",
            "FINDING tunnel-inventory count=3 expected_present=2 unexpected=1",
        )
        self.assertNotIn(PRIVATE_TUNNEL_NAME, completed.stdout + completed.stderr)

    def test_each_public_or_private_surface_deviation_is_a_finding(self):
        self.assert_findings({
            # A duplicate expected name cannot stand in for a missing one.
            "duplicate-tunnel-name": "FINDING tunnel-inventory count=3 expected_present=3 unexpected=0",
            "private-route": "FINDING private-routes 1 route(s) exist",
            "hostname-route": "FINDING hostname-routes 1 route(s) exist",
            # Pagination completeness: the origin A record sits on the second
            # DNS page, so stopping after the first page would report a clean zone.
            "dns-second-page-address": "FINDING zone-dns[naranjo.online] 1 address record(s) exist",
            # The hardening checks still cover the third platform zone.
            "platform-zone-c-unhardened": "FINDING zone-setting[hospedajedonlolo.com/min_tls_version] value=1.0 expected=1.2",
        })

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
        self.assertEqual(self.log_entries(), [])

    def test_malformed_token_stops_before_any_request(self):
        for malformed_token in (
            "unsafe token value with spaces",
            # One character too long and one too short for the classic shape:
            # the exact length is the guard, not a range.
            API_TOKEN + "x",
            API_TOKEN[:-1],
            "cf" + "ut_" + "A" * 40 + "z" * 8,
        ):
            with self.subTest(length=len(malformed_token)):
                malformed = self.run_script(
                    extra_env={"CLOUDFLARE_API_TOKEN": malformed_token},
                )
                self.assertEqual(malformed.returncode, 2)
                self.assertIn(
                    "CLOUDFLARE_API_TOKEN has an unsupported or unsafe format",
                    malformed.stderr,
                )
                self.assertNotIn(malformed_token, malformed.stdout + malformed.stderr)
                self.assertEqual(self.log_entries(), [])

    def test_the_prefixed_token_shape_is_accepted(self):
        prefixed = "cf" + "ut_" + "A" * 40 + "0123abcd"
        completed = self.run_script(
            mode="token-resource-bad-value",
            extra_env={"CLOUDFLARE_API_TOKEN": prefixed},
        )
        # It passes the format guard and reaches the token proof.
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("FINDING auth-resources", completed.stdout)
        self.assertNotIn(prefixed, completed.stdout + completed.stderr)

    def test_raw_mode_warns_and_python_ignores_an_inherited_pythonpath(self):
        # Every Python process that holds the token runs isolated, so a
        # PYTHONPATH in the caller's environment cannot load code into it.
        hijack = self.root / "hijack"
        hijack.mkdir()
        marker = self.root / "hijacked"
        (hijack / "sitecustomize.py").write_text(
            "open({!r}, 'a').close()\n".format(str(marker)), encoding="utf-8"
        )
        completed = self.run_script(
            "--raw",
            extra_env={"CLOUDFLARE_API_TOKEN": API_TOKEN, "PYTHONPATH": str(hijack)},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertFalse(marker.exists(), "an inherited PYTHONPATH loaded code")
        self.assertIn("RAW MODE", completed.stdout)
        self.assertIn("Never commit it", completed.stdout)
        self.assertIn(ACCOUNT_ID, completed.stdout)
        self.assertIn("auth token_status=active token_id=id:", completed.stdout)
        self.assertNotIn(TOKEN_ID, completed.stdout + completed.stderr)
        self.assertNotIn(
            TOKEN_ID,
            self.log_path.read_text(encoding="utf-8"),
        )

    def test_redaction_is_stable_distinct_and_opaque(self):
        program = (
            "resolve_tools\n"
            "redact sample-identifier-one\n"
            "redact sample-identifier-one\n"
            "redact sample-identifier-two\n"
            "redact ''\n"
        )
        completed = self.call_function(program)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        first, second, other, empty = completed.stdout.strip().splitlines()
        self.assertEqual(first, second, "a diff between two runs must be stable")
        self.assertNotEqual(first, other, "distinct inputs must stay distinct")
        self.assertTrue(first.startswith("id:"))
        self.assertNotIn("sample-identifier", first, "the pseudonym must not carry its input")
        self.assertEqual(empty, "none")

    def test_raw_mode_returns_the_identifier_verbatim(self):
        completed = self.call_function(
            "resolve_tools\nRAW=yes\nredact sample-identifier-one\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "sample-identifier-one")

    def test_redaction_fails_closed_without_a_digest_tool(self):
        # An empty pseudonym would collapse every identifier to one token and
        # make an audit diff look clean while hiding real change.
        completed = self.call_function("redact sample-identifier-one\n")
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("id:", completed.stdout)

    def test_only_allowed_zone_names_are_printed_in_redacted_mode(self):
        completed = self.call_function(
            "resolve_tools\n"
            "zone_label sloptube.fun\n"
            "zone_label hospedajedonlolo.com\n"
            "zone_label " + PRIVATE_ZONE_NAME + "\n"
            "RAW=yes\n"
            "zone_label " + PRIVATE_ZONE_NAME + "\n"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        unserved, platform, redacted, raw = completed.stdout.strip().splitlines()
        self.assertEqual(unserved, "sloptube.fun")
        self.assertEqual(platform, "hospedajedonlolo.com")
        self.assertRegex(redacted, r"^id:[0-9a-f]{12}$")
        self.assertEqual(raw, PRIVATE_ZONE_NAME)

    def run_reader(self, *argv, mode="healthy"):
        self.install_fake_cf(mode)
        return subprocess.run(
            [sys.executable, "-I", str(READER), "--cf-bin", str(self.bin_dir / "cf"), *argv],
            capture_output=True,
            text=True,
            env=self.environment({"CLOUDFLARE_API_TOKEN": API_TOKEN}),
        )

    def test_adapter_refuses_an_unreviewed_cf_version_on_its_own(self):
        # The adapter enforces the pin itself, not only through the script.
        completed = self.run_reader(
            "--operation", "zones-list", "--account-id", ACCOUNT_ID, mode="old-version"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("reviewed pinned version", completed.stderr)
        self.assertEqual([e["args"] for e in self.log_entries()], [["--version"]])

    def test_adapter_checks_the_schema_before_every_read(self):
        # The script's up-front schema check is a fast stop; the adapter still
        # proves the schema itself before the one read it runs.
        for mode in ("write-schema", "body-schema", "path-schema"):
            with self.subTest(mode=mode):
                self.log_path.unlink(missing_ok=True)
                completed = self.run_reader(
                    "--operation", "zones-list", "--account-id", ACCOUNT_ID, mode=mode
                )
                self.assertEqual(completed.returncode, 1)
                self.assertFalse(
                    any(e["args"][:2] == ["zones", "list"] for e in self.log_entries())
                )

    def test_adapter_rejects_hostile_arguments_before_running_cf(self):
        # The adapter validates every identifier before a cf process starts,
        # so no caller can smuggle an option or a second value into cf's argv.
        self.install_fake_cf()
        cf = str(self.bin_dir / "cf")
        hostile = (
            ("--operation", "zones-list", "--account-id", "--help"),
            ("--operation", "zones-list", "--account-id", ACCOUNT_ID + " --zone x"),
            ("--operation", "zones-list"),
            ("--operation", "dns-records", "--zone-id", "../" + ZONE_A_ID),
            ("--operation", "dns-records", "--zone-id", ZONE_A_ID, "--account-id", ACCOUNT_ID),
            ("--operation", "zone-setting", "--zone-id", ZONE_A_ID, "--setting-id", "ssl_recommender"),
            ("--operation", "tunnel-config", "--account-id", ACCOUNT_ID, "--tunnel-id", "x"),
            ("--operation", "user-token-get", "--token-id", "$(id)"),
        )
        for argv in hostile:
            with self.subTest(argv=argv):
                completed = subprocess.run(
                    [sys.executable, str(READER), "--cf-bin", cf, *argv],
                    capture_output=True,
                    text=True,
                    env=self.environment({"CLOUDFLARE_API_TOKEN": API_TOKEN}),
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(self.log_entries(), [])
        # The vacuity probe: a well-formed request does reach cf.
        completed = subprocess.run(
            [sys.executable, str(READER), "--cf-bin", cf, "--operation", "dns-records", "--zone-id", ZONE_A_ID],
            capture_output=True,
            text=True,
            env=self.environment({"CLOUDFLARE_API_TOKEN": API_TOKEN}),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(self.log_entries())


class CloudflareAccountAuditSourceTests(unittest.TestCase):
    """Source-level pins for properties the live API path cannot prove here."""

    @classmethod
    def setUpClass(cls):
        cls.shell_source = SCRIPT.read_text(encoding="utf-8")
        cls.shell_lines = cls.shell_source.splitlines()
        cls.reader_source = READER.read_text(encoding="utf-8")

    def test_no_raw_cloudflare_transport_or_curl_remains(self):
        combined = self.shell_source + self.reader_source
        raw_api = "api.cloudflare.com/" + "client"
        self.assertNotIn(raw_api, combined)
        self.assertNotRegex(combined, r"\bcurl\b")

    def test_every_provider_operation_is_allowlisted_at_its_reviewed_path(self):
        module = load_script("cloudflare_cf_read.py", module_name="cloudflare_cf_read_contract")
        operations = module.OPERATIONS
        self.assertEqual(set(operations), set(EXPECTED_OPERATIONS))
        for name, (command, api_path) in EXPECTED_OPERATIONS.items():
            with self.subTest(operation=name):
                self.assertEqual(operations[name].command, command)
                self.assertEqual(operations[name].api_path, api_path)
                self.assertNotIn(command[-1], {"create", "update", "delete", "edit", "cleanup"})

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
        self.assertEqual(
            self.shell_source.count('CLOUDFLARE_API_TOKEN="${CF_API_TOKEN_VALUE}"'),
            1,
        )
        self.assertIn('value = os.environ.get("CLOUDFLARE_API_TOKEN")', self.reader_source)
        self.assertNotIn('"--api-token"', self.reader_source)

    def test_the_credential_never_reaches_a_file_or_output(self):
        # Every non-comment line that touches the token value: none redirects
        # to a file, echoes, or prints it.
        uses = [
            line
            for line in self.shell_lines
            if ("CLOUDFLARE_API_TOKEN" in line or "CF_API_TOKEN_VALUE" in line)
            and not line.lstrip().startswith("#")
        ]
        self.assertTrue(uses)
        for line in uses:
            with self.subTest(line=line.strip()):
                self.assertNotIn(">", line, "the token is never redirected to a file")
                self.assertNotIn("echo", line)
                self.assertNotIn("printf", line)

    def test_write_verbs_are_absent_from_cf_runtime_command_construction(self):
        for verb in ("create", "update", "delete", "edit", "cleanup"):
            with self.subTest(verb=verb):
                self.assertNotIn(f'command.append("{verb}")', self.reader_source)
                self.assertNotIn(f'command.extend(("{verb}"', self.reader_source)

    def test_tracing_and_history_are_disabled_before_anything_runs(self):
        prologue = "\n".join(self.shell_lines[:60])
        self.assertIn("set +x", prologue)
        self.assertIn("set +o history", prologue)

    def test_raw_mode_carries_its_own_warning(self):
        self.assertIn("RAW MODE", self.shell_source)
        self.assertIn("Never commit it", self.shell_source)

    def test_expectations_match_the_three_site_target_state(self):
        for expected in (
            "readonly TUNNEL_A='naranjo-online'",
            "readonly TUNNEL_B='lidersea-com'",
            # The third site (issue #422): its zone, Tunnel, origin and signed
            # DNSSEC expectation, and every platform-zone check run for it.
            "readonly ZONE_C='hospedajedonlolo.com'",
            "readonly TUNNEL_C='hospedajedonlolo-com'",
            "readonly ORIGIN_C='http://hospedajedonlolo-com.hospedajedonlolo-com.svc.cluster.local:8080'",
            "readonly DNSSEC_C='active'",
            # The unserved owner zone ADR 0006 allows (amendment of 2026-11-02).
            "readonly ZONE_UNSERVED='sloptube.fun'",
            'audit_zone_settings "${ZONE_C}" "${zone_c_id}"',
            'audit_dnssec "${ZONE_C}" "${zone_c_id}" "${DNSSEC_C}"',
            'audit_tunnel_detail "${account_id}" "${TUNNEL_C}" "${ZONE_C}" "${ORIGIN_C}"',
            'audit_dns_records "${ZONE_C}" "${zone_c_id}" "$(tunnel_id_for "${TUNNEL_C}")"',
            'if [[ "${count}" == 3 && "${exact}" == true ]]; then',
            "http_status:404",
            "always_use_https on",
            "min_tls_version 1.2",
            "tls_1_3 on",
            "0rtt off",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.shell_source)
        # The unserved zone never meets a platform-only check.
        self.assertNotRegex(
            self.shell_source,
            r'audit_(zone_settings|dnssec|dns_records) "\$\{ZONE_UNSERVED\}"',
        )

    def test_unreadable_answers_are_findings_not_passes(self):
        # Fail-closed is the whole point: every branch that could not read an
        # answer must call finding(), never ok().
        unavailable = [
            line
            for line in self.shell_lines
            if "could not be read" in line or "could not be verified" in line
        ]
        self.assertGreaterEqual(len(unavailable), 8)
        for line in unavailable:
            with self.subTest(line=line.strip()):
                self.assertIn("finding ", line)


class CloudflareReaderGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_script("cloudflare_cf_read.py", module_name="cloudflare_cf_read_guards")

    def test_schema_requires_method_body_and_exact_path(self):
        operation = self.module.Operation(("zones", "list"), "/zones", "array")
        cases = (
            {"httpMethod": "POST", "path": "/zones", "hasRequestBody": False},
            {"httpMethod": "GET", "path": "/zones", "hasRequestBody": True},
            {"httpMethod": "GET", "path": "/zones"},
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

    def test_api_token_shapes_are_exact(self):
        valid = ("A" * 40, "cf" + "at_" + "B" * 40 + "0123abcd")
        invalid = ("A" * 39, "A" * 41, "A" * 39 + " ", "cf" + "at_" + "B" * 40 + "0123abcg", "x" * 200)
        for value in valid:
            with self.subTest(valid=len(value)), mock.patch.dict(
                os.environ, {"CLOUDFLARE_API_TOKEN": value}
            ):
                self.assertEqual(self.module.api_token_from_environment(), value)
        for value in invalid:
            with self.subTest(invalid=len(value)), mock.patch.dict(
                os.environ, {"CLOUDFLARE_API_TOKEN": value}
            ):
                with self.assertRaises(self.module.AuditReadError):
                    self.module.api_token_from_environment()

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

    def test_process_timeout_is_a_sanitized_failure(self):
        with mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="cf", timeout=30),
        ):
            with self.assertRaisesRegex(self.module.AuditReadError, "30-second deadline"):
                self.module.run_process("/usr/bin/false", ("zones", "list"), scratch="/tmp")

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

    def test_a_repeated_page_fails_closed(self):
        # A CLI that ignored --page would return page one again; the repeat is
        # refused at once rather than counted twice into an inventory.
        key = "guard-test-repeat"
        self.module.OPERATIONS[key] = self.module.Operation(("zones", "list"), "/zones", "array", True)
        pages = [json.dumps(["x"]).encode(), json.dumps(["x"]).encode(), b"[]"]
        try:
            with mock.patch.object(self.module, "validate_schema"), mock.patch.object(
                self.module, "run_process", side_effect=pages
            ):
                with self.assertRaisesRegex(self.module.AuditReadError, "repeated"):
                    self.module.read_operation(
                        "/usr/bin/false", key, Namespace(account_id=None), "/tmp", api_token=API_TOKEN
                    )
        finally:
            self.module.OPERATIONS.pop(key, None)

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
