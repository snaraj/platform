#!/usr/bin/env python3
"""Bounded, read-only adapter for the Cloudflare ``cf`` CLI.

The owner-facing account audit calls this adapter instead of building raw API
requests. Every operation is fixed here, checked against ``cf schema`` before
execution, and required to remain a GET with no request body. The adapter
prints the API result in a small ``{"result": ...}`` envelope so the audit's
assertion and redaction layer stays reviewable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


APPROVED_CF_VERSION = "v1.0.0-beta.5"
COMMAND_TIMEOUT_SECONDS = 30
MAX_COMMAND_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
PAGE_SIZE = 50
MAX_PAGES = 100

HEX_ID = re.compile(r"^[0-9a-f]{32}$")
TUNNEL_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
PROFILE = re.compile(r"^[A-Za-z0-9_-]+$")
API_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
ZONE_NAME = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SETTING_IDS = frozenset(
    {"always_use_https", "min_tls_version", "tls_1_3", "0rtt", "ssl", "security_header"}
)


class AuditReadError(RuntimeError):
    """A sanitized failure safe to show to the operator."""


@dataclass(frozen=True)
class Operation:
    command: tuple[str, ...]
    api_path: str
    result_type: str
    paginated: bool = False


OPERATIONS = {
    "zones-list": Operation(("zones", "list"), "/zones", "array", True),
    "account-subscriptions": Operation(
        ("accounts", "subscriptions", "get"),
        "/{account_or_zone}/{account_or_zone_id}/subscriptions",
        "array",
    ),
    "user-subscriptions": Operation(
        ("user", "subscriptions", "get"), "/user/subscriptions", "array"
    ),
    "zone-subscription": Operation(
        ("zones", "subscriptions", "get"), "/zones/{zone_id}/subscription", "object"
    ),
    "billing-history": Operation(
        ("accounts", "billing", "history", "list"),
        "/accounts/{account_id}/billing/history",
        "array",
        True,
    ),
    "unpaid-invoices": Operation(
        ("accounts", "billing", "getUnpaidInvoices"),
        "/accounts/{account_id}/billing/unpaid-invoice",
        "object",
    ),
    "bad-debt": Operation(
        ("accounts", "billing", "getBadDebt"),
        "/accounts/{account_id}/billing/bad-debt",
        "object",
    ),
    "billing-usage-info-v1": Operation(
        ("billing", "usage", "get-info-v1"),
        "/accounts/{account_id}/billable-usage/info",
        "object",
    ),
    "billing-usage-v1": Operation(
        ("billing", "usage", "get-v1"),
        "/accounts/{account_id}/billable-usage",
        "array",
    ),
    "billable-metrics": Operation(
        ("billing", "usage", "get-account-billable-metrics"),
        "/accounts/{account_id}/billable/usage/billable-metrics",
        "array",
    ),
    "certificate-packs": Operation(
        ("ssl", "certificate-packs", "list"),
        "/zones/{zone_id}/ssl/certificate_packs",
        "array",
        True,
    ),
    "certificate-pack-quota": Operation(
        ("ssl", "certificate-packs", "quota", "get"),
        "/zones/{zone_id}/ssl/certificate_packs/quota",
        "object",
    ),
    "zone-setting": Operation(
        ("zones", "settings", "get"),
        "/zones/{zone_id}/settings/{setting_id}",
        "object",
    ),
    "dnssec": Operation(("dns", "dnssec", "get"), "/zones/{zone_id}/dnssec", "object"),
    "tunnels-list": Operation(
        ("tunnels", "list"), "/accounts/{account_id}/tunnels", "array", True
    ),
    "tunnel-config": Operation(
        ("tunnels", "config", "get"),
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        "object",
    ),
    "tunnel-connections": Operation(
        ("tunnels", "connections", "list"),
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
        "array",
    ),
    "private-routes": Operation(
        ("network", "routes", "cidr", "list"),
        "/accounts/{account_id}/teamnet/routes",
        "array",
        True,
    ),
    "warp-profiles": Operation(
        ("zero-trust", "devices", "profiles", "custom", "list"),
        "/accounts/{account_id}/devices/policies",
        "array",
    ),
    "dns-records": Operation(
        ("dns", "records", "list"), "/zones/{zone_id}/dns_records", "array", True
    ),
    "user-token-verify": Operation(
        ("user", "tokens", "verify"), "/user/tokens/verify", "object"
    ),
    "user-token-get": Operation(
        ("user", "tokens", "get"), "/user/tokens/{token_id}", "object"
    ),
}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--cf-bin", required=True)
    result.add_argument("--validate-schemas", action="store_true")
    result.add_argument("--operation", choices=("auth-whoami", *OPERATIONS))
    result.add_argument("--profile")
    result.add_argument("--account-id")
    result.add_argument("--zone-id")
    result.add_argument("--zone-name")
    result.add_argument("--setting-id")
    result.add_argument("--tunnel-id")
    result.add_argument("--token-id")
    return result


def validate_identifier(value: str | None, pattern: re.Pattern[str], field: str) -> str:
    if value is None or pattern.fullmatch(value) is None:
        raise AuditReadError(f"{field} is missing or malformed")
    return value


def api_token_from_environment() -> str | None:
    value = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not value:
        return None
    if API_TOKEN.fullmatch(value) is None:
        raise AuditReadError("CLOUDFLARE_API_TOKEN has an unsupported or unsafe format")
    return value


def minimal_environment(
    account_id: str | None,
    scratch: str,
    *,
    profile_mode: bool = False,
    api_token: str | None = None,
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "HOME": os.environ.get("HOME", "") if profile_mode else scratch,
        "TMPDIR": scratch,
        "DO_NOT_TRACK": "1",
        "CF_SEND_TELEMETRY": "false",
        "WRANGLER_SEND_METRICS": "false",
        "NO_COLOR": "1",
        "CF_NO_OSC_PROGRESS": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if profile_mode and os.environ.get("XDG_CONFIG_HOME"):
        environment["XDG_CONFIG_HOME"] = os.environ["XDG_CONFIG_HOME"]
    elif not profile_mode:
        environment["XDG_CONFIG_HOME"] = scratch
    if api_token is not None:
        environment["CLOUDFLARE_API_TOKEN"] = api_token
    if account_id is not None:
        environment["CLOUDFLARE_ACCOUNT_ID"] = account_id
    return environment


def run_process(
    cf_bin: str,
    arguments: Sequence[str],
    *,
    account_id: str | None = None,
    scratch: str,
    profile_mode: bool = False,
    api_token: str | None = None,
) -> bytes:
    try:
        completed = subprocess.run(
            [cf_bin, *arguments],
            cwd=scratch,
            env=minimal_environment(
                account_id, scratch, profile_mode=profile_mode, api_token=api_token
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AuditReadError("cf command exceeded the 30-second deadline") from exc
    except OSError as exc:
        raise AuditReadError("cf command could not be executed") from exc

    if completed.returncode != 0:
        raise AuditReadError(f"cf command failed with exit {completed.returncode}")
    if len(completed.stdout) > MAX_COMMAND_BYTES or len(completed.stderr) > MAX_COMMAND_BYTES:
        raise AuditReadError("cf command exceeded the 5 MiB output limit")
    return completed.stdout


def parse_json(payload: bytes, expected_type: str) -> Any:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditReadError("cf returned malformed JSON") from exc
    if expected_type == "array" and not isinstance(value, list):
        raise AuditReadError("cf returned an unexpected non-array result")
    if expected_type == "object" and not isinstance(value, dict):
        raise AuditReadError("cf returned an unexpected non-object result")
    return value


def cf_version(cf_bin: str, scratch: str) -> str:
    output = run_process(cf_bin, ("--version",), scratch=scratch).decode("utf-8", "replace")
    match = re.search(r"\bv[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\b", output)
    if match is None:
        raise AuditReadError("cf version output was not recognized")
    version = match.group(0)
    if version != APPROVED_CF_VERSION:
        raise AuditReadError("cf version is not the reviewed pinned version")
    return version


def validate_schema(cf_bin: str, operation: Operation, scratch: str) -> dict[str, Any]:
    payload = run_process(cf_bin, ("schema", *operation.command), scratch=scratch)
    schema = parse_json(payload, "object")
    if schema.get("httpMethod") != "GET":
        raise AuditReadError("cf schema did not prove a GET request")
    if schema.get("hasRequestBody") is not False:
        raise AuditReadError("cf schema unexpectedly permits a request body")
    if schema.get("path") != operation.api_path:
        raise AuditReadError("cf schema path differs from the reviewed endpoint")
    return schema


def validate_inputs(args: argparse.Namespace) -> tuple[bool, str | None]:
    if args.validate_schemas:
        if args.operation is not None:
            raise AuditReadError("choose schema validation or one operation")
        return False, None
    if args.operation is None:
        raise AuditReadError("an operation is required")

    api_token = api_token_from_environment()
    profile_mode = args.profile is not None
    if profile_mode == (api_token is not None):
        raise AuditReadError("select exactly one authentication source")
    if profile_mode:
        validate_identifier(args.profile, PROFILE, "profile")

    if args.operation == "auth-whoami" and not profile_mode:
        raise AuditReadError("auth-whoami requires a named profile")
    if args.operation in {"user-token-verify", "user-token-get"} and api_token is None:
        raise AuditReadError("token inspection requires CLOUDFLARE_API_TOKEN")

    account_ops = {
        "account-subscriptions",
        "billing-history",
        "unpaid-invoices",
        "bad-debt",
        "billing-usage-info-v1",
        "billing-usage-v1",
        "billable-metrics",
        "tunnels-list",
        "tunnel-config",
        "tunnel-connections",
        "private-routes",
        "warp-profiles",
    }
    zone_ops = {
        "zone-subscription",
        "certificate-packs",
        "certificate-pack-quota",
        "zone-setting",
        "dnssec",
        "dns-records",
    }
    tunnel_ops = {"tunnel-config", "tunnel-connections"}

    if args.operation in account_ops:
        validate_identifier(args.account_id, HEX_ID, "account id")
    elif args.account_id is not None:
        raise AuditReadError("account id is not valid for this operation")

    if args.operation in zone_ops:
        validate_identifier(args.zone_id, HEX_ID, "zone id")
    elif args.zone_id is not None:
        raise AuditReadError("zone id is not valid for this operation")

    if args.operation == "zones-list":
        validate_identifier(args.zone_name, ZONE_NAME, "zone name")
    elif args.zone_name is not None:
        raise AuditReadError("zone name is not valid for this operation")

    if args.operation == "zone-setting":
        if args.setting_id not in SETTING_IDS:
            raise AuditReadError("zone setting is outside the read allowlist")
    elif args.setting_id is not None:
        raise AuditReadError("zone setting is not valid for this operation")

    if args.operation in tunnel_ops:
        validate_identifier(args.tunnel_id, TUNNEL_ID, "tunnel id")
    elif args.tunnel_id is not None:
        raise AuditReadError("tunnel id is not valid for this operation")

    if args.operation == "user-token-get":
        validate_identifier(args.token_id, HEX_ID, "token id")
    elif args.token_id is not None:
        raise AuditReadError("token id is not valid for this operation")

    return profile_mode, api_token


def command_arguments(
    key: str, args: argparse.Namespace, *, page: int | None = None
) -> tuple[list[str], str | None]:
    if key == "auth-whoami":
        return ["auth", "whoami", "--profile", args.profile], None

    operation = OPERATIONS[key]
    command = list(operation.command)
    account_id = args.account_id

    if key == "zones-list":
        command.extend(("--name", args.zone_name))
    elif key == "zone-subscription":
        command.extend(("--zone", args.zone_id))
    elif key == "certificate-packs":
        command.extend(("--zone", args.zone_id, "--status", "all"))
    elif key == "certificate-pack-quota":
        command.extend(("--zone", args.zone_id))
    elif key == "zone-setting":
        command.extend((args.setting_id, "--zone", args.zone_id))
    elif key == "dnssec":
        command.extend(("--zone", args.zone_id))
    elif key == "tunnels-list":
        command.extend(("--is-deleted=false", "--tun-types", "cfd_tunnel"))
    elif key == "tunnel-config":
        command.append(args.tunnel_id)
    elif key == "tunnel-connections":
        command.extend(("--tunnel-id", args.tunnel_id))
    elif key == "private-routes":
        command.append("--is-deleted=false")
    elif key == "warp-profiles":
        command.extend(("--profile-type", "warp"))
    elif key == "dns-records":
        command.extend(("--zone", args.zone_id))
    elif key == "user-token-get":
        command.append(args.token_id)

    if operation.paginated:
        if page is None:
            raise AuditReadError("internal pagination state is missing")
        command.extend(("--per-page", str(PAGE_SIZE), "--page", str(page)))
    if args.profile is not None:
        command.extend(("--profile", args.profile))
    return command, account_id


def read_operation(
    cf_bin: str,
    key: str,
    args: argparse.Namespace,
    scratch: str,
    *,
    profile_mode: bool,
    api_token: str | None,
) -> Any:
    if key == "auth-whoami":
        command, account_id = command_arguments(key, args)
        return parse_json(
            run_process(
                cf_bin,
                command,
                account_id=account_id,
                scratch=scratch,
                profile_mode=True,
            ),
            "object",
        )

    operation = OPERATIONS[key]
    validate_schema(cf_bin, operation, scratch)
    if not operation.paginated:
        command, account_id = command_arguments(key, args)
        return parse_json(
            run_process(
                cf_bin,
                command,
                account_id=account_id,
                scratch=scratch,
                profile_mode=profile_mode,
                api_token=api_token,
            ),
            operation.result_type,
        )

    combined: list[Any] = []
    seen_pages: set[str] = set()
    for page in range(1, MAX_PAGES + 1):
        command, account_id = command_arguments(key, args, page=page)
        result = parse_json(
            run_process(
                cf_bin,
                command,
                account_id=account_id,
                scratch=scratch,
                profile_mode=profile_mode,
                api_token=api_token,
            ),
            "array",
        )
        if not result:
            return combined
        fingerprint = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if fingerprint in seen_pages:
            raise AuditReadError("cf pagination repeated a non-empty page")
        seen_pages.add(fingerprint)
        combined.extend(result)
        if len(json.dumps(combined, separators=(",", ":")).encode("utf-8")) > MAX_TOTAL_BYTES:
            raise AuditReadError("cf collection exceeded the 5 MiB total limit")
    raise AuditReadError("cf collection exceeded the 100-page limit")


def main() -> int:
    args = parser().parse_args()
    try:
        profile_mode, api_token = validate_inputs(args)
        cf_path = Path(args.cf_bin)
        if not cf_path.is_absolute() or not cf_path.is_file() or not os.access(cf_path, os.X_OK):
            raise AuditReadError("cf executable is unavailable")
        cf_bin = str(cf_path.resolve())
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix="cloudflare-cf-read.") as scratch:
                version = cf_version(cf_bin, scratch)
                if args.validate_schemas:
                    validated = []
                    for name, operation in OPERATIONS.items():
                        schema = validate_schema(cf_bin, operation, scratch)
                        validated.append(
                            {
                                "operation": name,
                                "method": schema["httpMethod"],
                                "path": schema["path"],
                            }
                        )
                    print(
                        json.dumps(
                            {"version": version, "operations": validated},
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                    return 0
                result = read_operation(
                    cf_bin,
                    args.operation,
                    args,
                    scratch,
                    profile_mode=profile_mode,
                    api_token=api_token,
                )
                print(json.dumps({"result": result}, separators=(",", ":")))
                return 0
        finally:
            os.umask(old_umask)
    except AuditReadError as exc:
        print(f"cloudflare-cf-read: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
