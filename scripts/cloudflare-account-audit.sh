#!/usr/bin/env bash
# OWNER-RUN, read-only Cloudflare account/zone audit for the facts that the
# token-free edge probe cannot observe.
#
# WHY THIS EXISTS. scripts/edge-probe.sh proves behaviour from outside with no
# credential. Behaviour cannot say which setting produced it, and it cannot see
# anything with no externally observable effect: plan and subscription state,
# the Tunnel and connector inventory, the DNS record set, managed-HSTS
# ownership, or whether a Zero Trust private-network surface exists. This
# script reads exactly those facts through authenticated GET requests and
# nothing else.
#
# CREDENTIAL HANDLING. The audit accepts exactly one explicit cf authentication
# source: a named OAuth profile, or a short-lived API token in
# CLOUDFLARE_API_TOKEN. The token reaches cf only through its environment; it is
# never accepted in argv, printed, or written to a file. Legacy keys, account
# context, zone context, and mixed authentication are rejected.
#
# OUTPUT IS REDACTED BY DEFAULT. Account, zone, Tunnel and connector
# identifiers are replaced with stable short pseudonyms so two runs diff
# cleanly without publishing an inventory of identifiers. The mapping is a
# domain-separated SHA-256 prefix: the same input gives the same pseudonym
# across runs and hosts, which is what makes a diff meaningful, and the inputs
# are 128-bit random identifiers, so a pseudonym discloses nothing. --raw
# prints real identifiers for the owner's eyes only and says so loudly.
#
# FAIL CLOSED. Every allowlisted cf command is checked against `cf schema`
# before use and must remain a GET with no body at its reviewed path. Transport
# failure, malformed JSON, a repeated or unbounded page, or unexpected schema
# is a finding that fails the run. An unknown answer is never a pass.
set -Eeuo pipefail
set +x
set +o history

# The adapter pins both the cf beta and every API path. A cf upgrade fails
# closed until its generated schema and output behavior receive review.
readonly SCHEMA='cloudflare-account-audit/2'
readonly REDACTION_DOMAIN='website-infrastructure/cloudflare-account-audit/v1'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly CF_READER="${SCRIPT_DIR}/cloudflare_cf_read.py"

# The audited target state, per ADR 0015 (two per-site Tunnels) and the
# 2026-08-12 edge attestation. Zone names are the site identities; Tunnel names
# are the site identity tuples.
readonly ZONE_A='naranjo.online'
readonly ZONE_B='lidersea.com'
readonly TUNNEL_A='naranjo-online'
readonly TUNNEL_B='lidersea-com'
readonly ORIGIN_A='http://naranjo-online.naranjo-online.svc.cluster.local:8080'
readonly ORIGIN_B='http://lidersea-com.lidersea-com.svc.cluster.local:8080'
# naranjo.online is signed; lidersea.com stays unsigned until the owner's
# signing ceremony, so "disabled" is its expected DNSSEC state today. If the
# ceremony happens, this expectation moves in the same reviewed change.
readonly DNSSEC_A='active'
readonly DNSSEC_B='disabled'

# grep is resolved absolutely and every pattern is passed with -e: an
# interactive shell that shims grep to ugrep parses a dash-leading pattern as
# an option and silently returns nothing.
resolve_grep() {
  local candidate
  for candidate in /usr/bin/grep /bin/grep; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  command -v grep
}
GREP="$(resolve_grep)"
readonly GREP

RAW=no
FINDINGS=0
CHECKS=0
DIGEST_TOOL=''
WORKDIR=''
CF_BIN=''
CF_VERSION=''
CF_BIN_DIGEST=''
CF_PROFILE=''
CF_AUTH_MODE=''
CF_API_TOKEN_VALUE=''
AUTH_READ=no

usage() {
  cat <<'USAGE'
Usage:
  scripts/cloudflare-account-audit.sh --profile NAME [--raw]
  CLOUDFLARE_API_TOKEN=... scripts/cloudflare-account-audit.sh [--raw]
  scripts/cloudflare-account-audit.sh --self-test
  scripts/cloudflare-account-audit.sh --help

Read-only Cloudflare account/zone audit through Cloudflare's cf CLI. Owner-run
only. Every provider request is schema-checked as GET with no request body; the
script never creates, updates, deletes, plans, or applies anything.

Authentication (choose exactly one):
  --profile NAME          A dedicated named cf OAuth profile with the narrowest
                          read-only scopes needed by this audit.
  CLOUDFLARE_API_TOKEN    A short-lived read-only token supplied only through
                          the environment. A complete zero-charge proof needs
                          Billing Read and the resource read permissions used
                          by this audit. API Tokens Read is also required so the
                          token's lifetime and permissions can be proved.

Options:
  --raw        Print real identifiers instead of stable pseudonyms. For the
               owner's eyes only: the output then contains account, zone,
               Tunnel and connector identifiers and must never be committed,
               pasted into an issue, pull request, comment or ticket, or
               shared.
  --self-test  Local invariant check: tooling, redaction determinism, the
               pinned cf version, and proof from cf schema that every provider
               request is a GET with no body at its reviewed path. It reads no
               credential and makes no Cloudflare account request.
  --help       This text.

What is audited (all read-only):
  * account, user, and zone subscriptions: zero price, permanent Free state
  * billing coverage, current-period costs, complete billing history, unpaid
    invoices, and bad debt: every monetary amount exactly zero
  * certificate packs and Advanced Certificate Manager quota: free-only
  * zone settings: always_use_https, min_tls_version, tls_1_3, 0rtt, ssl, and
    that Cloudflare-managed HSTS stays off because the application owns it
  * DNSSEC status against the per-zone expectation
  * Tunnel inventory: exactly the two expected per-site Tunnels, one public
    hostname rule plus a terminal 404 each, and no idle connector
  * no Zero Trust private-network surface: no private routes, no WARP profile
  * DNS inventory: exactly one proxied apex CNAME per zone targeting its own
    Tunnel, no origin A/AAAA anywhere, and no unexpected record
  * the selected cf credential: authenticated, valid, expiring, and read-only
    as far as its reported OAuth scopes or token permission groups can prove

Exit codes: 0 all checks passed, 1 one or more findings, 2 usage or tooling
error. A check that could not be completed counts as a finding.
USAGE
}

die() {
  printf 'cloudflare-account-audit: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  CF_API_TOKEN_VALUE=''
  unset CF_API_TOKEN_VALUE
  if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
    rm -rf -- "${WORKDIR}"
  fi
}

finding() {
  printf 'FINDING %s\n' "$*"
  FINDINGS=$(( FINDINGS + 1 ))
}

ok() {
  printf 'OK %s\n' "$*"
}

check() {
  CHECKS=$(( CHECKS + 1 ))
}

resolve_tools() {
  CF_BIN="$(command -v cf || true)"
  [[ -n "${CF_BIN}" && -x "${CF_BIN}" ]] || die 'Cloudflare cf is required; this script never installs tools'
  command -v python3 >/dev/null 2>&1 || die 'python3 is required; this script never installs tools'
  command -v jq >/dev/null 2>&1 || die 'jq is required; this script never installs tools'
  [[ -x "${CF_READER}" ]] || die 'the reviewed Cloudflare cf adapter is missing or not executable'
  if command -v sha256sum >/dev/null 2>&1; then
    DIGEST_TOOL='sha256sum'
  elif command -v shasum >/dev/null 2>&1; then
    DIGEST_TOOL='shasum -a 256'
  else
    die 'a SHA-256 tool (sha256sum or shasum) is required'
  fi
  CF_VERSION="$(DO_NOT_TRACK=1 "${CF_BIN}" --version | sed -n -E 's/.*(v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?).*/\1/p' | head -n 1)"
  [[ "${CF_VERSION}" == v1.0.0-beta.5 ]] || die 'cf must be the reviewed pinned version v1.0.0-beta.5'
  # shellcheck disable=SC2086 # DIGEST_TOOL is a fixed one- or two-word command
  CF_BIN_DIGEST="$(${DIGEST_TOOL} "${CF_BIN}" | cut -d ' ' -f 1)"
}

# Stable pseudonym for one identifier. Domain-separated so a value hashed here
# can never collide with the same value hashed for another purpose, and
# unsalted so two audits of the same account diff cleanly.
pseudonym() {
  local value="$1" digest
  if [[ -z "${value}" ]]; then
    printf 'none\n'
    return 0
  fi
  # Fail closed rather than emit an empty pseudonym: a run where every
  # identifier collapsed to the same token would look like a clean diff.
  [[ -n "${DIGEST_TOOL}" ]] || die 'the digest tool was never resolved; redaction cannot be trusted'
  # shellcheck disable=SC2086 # DIGEST_TOOL is a fixed one- or two-word command
  digest="$(printf '%s|%s' "${REDACTION_DOMAIN}" "${value}" | ${DIGEST_TOOL} | cut -c1-12)"
  printf 'id:%s\n' "${digest}"
}

redact() {
  local value="$1"
  if [[ "${RAW}" == yes ]]; then
    printf '%s\n' "${value}"
  else
    pseudonym "${value}"
  fi
}

select_authentication() {
  local variable
  for variable in \
    CF_API_TOKEN \
    CF_ACCOUNT_ID \
    CF_ZONE_ID \
    CLOUDFLARE_API_KEY \
    CLOUDFLARE_EMAIL \
    CLOUDFLARE_API_USER_SERVICE_KEY \
    CLOUDFLARE_ACCOUNT_ID \
    CLOUDFLARE_ZONE_ID; do
    if [[ -n "${!variable:-}" ]]; then
      die "unset ${variable}; legacy credentials and target context may not affect this audit"
    fi
  done

  if [[ -n "${CF_PROFILE}" && -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    die 'choose either --profile or CLOUDFLARE_API_TOKEN, never both'
  elif [[ -n "${CF_PROFILE}" ]]; then
    [[ "${CF_PROFILE}" =~ ^[A-Za-z0-9_-]+$ ]] || die 'the cf profile name is malformed'
    CF_AUTH_MODE=profile
  elif [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    (( ${#CLOUDFLARE_API_TOKEN} >= 20 && ${#CLOUDFLARE_API_TOKEN} <= 512 )) || \
      die 'CLOUDFLARE_API_TOKEN has an unsupported or unsafe format'
    [[ "${CLOUDFLARE_API_TOKEN}" =~ ^[A-Za-z0-9_-]+$ ]] || \
      die 'CLOUDFLARE_API_TOKEN has an unsupported or unsafe format'
    CF_AUTH_MODE=api-token
    CF_API_TOKEN_VALUE="${CLOUDFLARE_API_TOKEN}"
    unset CLOUDFLARE_API_TOKEN
  else
    die 'set --profile NAME or a short-lived CLOUDFLARE_API_TOKEN for an account audit'
  fi
}

cf_read() {
  local arguments=(--cf-bin "${CF_BIN}")
  if [[ "${CF_AUTH_MODE}" == profile ]]; then
    arguments+=(--profile "${CF_PROFILE}")
    python3 "${CF_READER}" "${arguments[@]}" "$@"
  else
    CLOUDFLARE_API_TOKEN="${CF_API_TOKEN_VALUE}" \
      python3 "${CF_READER}" "${arguments[@]}" "$@"
  fi
}

validate_cf_schemas() {
  python3 "${CF_READER}" --cf-bin "${CF_BIN}" --validate-schemas
}

audit_profile_auth() {
  local whoami authenticated valid account_count scope_count non_read expiry
  whoami="$(cf_read --operation auth-whoami 2>/dev/null || true)"
  AUTH_READ=yes
  if [[ -z "${whoami}" ]] || ! jq -e '.result | type == "object"' >/dev/null 2>&1 <<<"${whoami}"; then
    finding 'auth the selected cf profile could not be verified; an audit never proceeds on unproven authentication'
    return 1
  fi
  authenticated="$(jq -r '.result.authenticated // false | tostring' <<<"${whoami}")"
  valid="$(jq -r '.result.tokenValid // false | tostring' <<<"${whoami}")"
  account_count="$(jq -r '.result.accounts // [] | length' <<<"${whoami}")"
  if [[ "${authenticated}" == true && "${valid}" == true && "${account_count}" -ge 1 ]]; then
    ok "auth authenticated=true token_valid=true account_count=${account_count}"
  else
    finding "auth authenticated=${authenticated} token_valid=${valid} account_count=${account_count}"
    return 1
  fi

  check
  scope_count="$(jq -r '.result.scopes // [] | length' <<<"${whoami}")"
  non_read="$(jq -r '[
    .result.scopes[]? |
    select((. == "openid" or . == "offline" or . == "offline_access" or . == "profile" or . == "email" or test("(^|[.:_-])read$"; "i")) | not)
  ] | unique | length' <<<"${whoami}")"
  if [[ "${scope_count}" -gt 0 && "${non_read}" == 0 ]]; then
    ok "auth-scope all ${scope_count} reported OAuth scope(s) are read-only by name"
  elif [[ "${scope_count}" == 0 ]]; then
    finding 'auth-scope cf reported no OAuth scopes, so least privilege could not be verified'
  else
    finding "auth-scope ${non_read} of ${scope_count} reported OAuth scope(s) are not recognized read-only scopes; use a dedicated read-only profile"
  fi

  check
  expiry="$(jq -r '.result.expiresAt // "" | tostring' <<<"${whoami}")"
  if [[ -n "${expiry}" ]]; then
    ok 'auth-expiry access-token expiry metadata is present; the OAuth profile persists through refresh until deleted'
  else
    finding 'auth-expiry cf reported no access-token expiry metadata'
  fi
}

audit_api_token_auth() {
  local verify detail token_id status non_read permission_count expiry expiry_epoch now_epoch
  verify="$(cf_read --operation user-token-verify 2>/dev/null || true)"
  AUTH_READ=yes
  if [[ -z "${verify}" ]] || ! jq -e '.result | type == "object"' >/dev/null 2>&1 <<<"${verify}"; then
    finding 'auth the API token could not be verified; an audit never proceeds on an unproven credential'
    return 1
  fi
  status="$(jq -r '.result.status // "unknown"' <<<"${verify}")"
  token_id="$(jq -r '.result.id // ""' <<<"${verify}")"
  if [[ "${status}" != active || ! "${token_id}" =~ ^[0-9a-f]{32}$ ]]; then
    finding "auth token_status=${status} token_id_present=$([[ -n "${token_id}" ]] && printf true || printf false)"
    return 1
  fi
  ok "auth token_status=active token_id=$(pseudonym "${token_id}")"

  check
  detail="$(cf_read --operation user-token-get --token-id "${token_id}" 2>/dev/null || true)"
  if [[ -z "${detail}" ]] || ! jq -e '.result | type == "object"' >/dev/null 2>&1 <<<"${detail}"; then
    finding 'auth-scope the token definition could not be read; add API Tokens Read so least privilege can be proved'
    return 0
  fi
  permission_count="$(jq -r '[.result.policies[]?.permission_groups[]?] | length' <<<"${detail}")"
  non_read="$(jq -r '[
    .result.policies[]? as $policy |
    $policy.permission_groups[]? |
    select(($policy.effect // "allow") != "allow" or ((.name // "") | test(" Read$") | not))
  ] | length' <<<"${detail}")"
  if [[ "${permission_count}" -gt 0 && "${non_read}" == 0 ]]; then
    ok "auth-scope all ${permission_count} token permission group(s) are read-only"
  else
    finding "auth-scope permission_groups=${permission_count} non_read=${non_read}; the token must contain only allow rules for Read permissions"
  fi

  check
  expiry="$(jq -r '.result.expires_on // ""' <<<"${detail}")"
  expiry_epoch="$(jq -r 'try (.result.expires_on | fromdateiso8601) catch 0' <<<"${detail}")"
  now_epoch="$(date -u +%s)"
  if [[ -n "${expiry}" && "${expiry_epoch}" =~ ^[0-9]+$ && "${expiry_epoch}" -gt "${now_epoch}" && $(( expiry_epoch - now_epoch )) -le 3600 ]]; then
    ok 'auth-expiry the API token expires within 60 minutes'
  else
    finding 'auth-expiry the API token must carry a valid expiry no more than 60 minutes from now'
  fi
}

audit_auth() {
  check
  if [[ "${CF_AUTH_MODE}" == profile ]]; then
    audit_profile_auth
  else
    audit_api_token_auth
  fi
}

# Resolve one zone by name. Echoes "<zone_id> <account_id>" and prints nothing
# else, so it is safe to call from a command substitution.
zone_identity() {
  local name="$1" zones
  zones="$(cf_read --operation zones-list --zone-name "${name}" 2>/dev/null || true)"
  [[ -n "${zones}" ]] || return 1
  [[ "$(jq -r '.result | length' <<<"${zones}")" == 1 ]] || return 1
  jq -e '.result[0].id | type == "string" and test("^[0-9a-f]{32}$")' >/dev/null 2>&1 <<<"${zones}" || return 1
  jq -e '.result[0].account.id | type == "string" and test("^[0-9a-f]{32}$")' >/dev/null 2>&1 <<<"${zones}" || return 1
  jq -r '.result[0] | (.id // "") + " " + (.account.id // "")' <<<"${zones}"
}

audit_subscription_result() {
  local label="$1" response="$2" disallowed total
  total="$(jq -r '.result | length' <<<"${response}")"
  disallowed="$(jq -r '[.result[]? | select(
    ((.price | type) != "number") or (.price != 0) or
    (((.rate_plan.id // .rate_plan.public_name // .rate_plan.name // "") | test("free"; "i")) | not) or
    ((.trial // false) != false) or
    (.rate_plan.is_contract != false) or
    (.rate_plan.externally_managed != false) or
    ((.state // "") | test("trial|awaiting"; "i"))
  )] | length' <<<"${response}")"
  if [[ "${disallowed}" == 0 ]]; then
    ok "${label} all ${total} subscription(s) are permanent, zero-priced Free plans"
  else
    finding "${label} ${disallowed} of ${total} subscription(s) have nonzero, trial, contract, external, ambiguous, or non-Free state"
  fi
}

audit_account_subscriptions() {
  local account_id="$1" response
  check
  response="$(cf_read --operation account-subscriptions --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'account-subscriptions the subscription inventory could not be read completely'
    return 0
  fi
  audit_subscription_result account-subscriptions "${response}"
}

audit_user_subscriptions() {
  local response
  check
  response="$(cf_read --operation user-subscriptions 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'user-subscriptions the user-level subscription inventory could not be read'
    return 0
  fi
  audit_subscription_result user-subscriptions "${response}"
}

audit_billing_coverage() {
  local account_id="$1" response covered subscriptions
  check
  response="$(cf_read --operation billing-usage-info-v1 --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'billing-coverage the current-period billing coverage could not be read; zero charge is unproved'
    return 0
  fi
  covered="$(jq -r '.result.covered // false | tostring' <<<"${response}")"
  subscriptions="$(jq -r 'if (.result.subscriptions | type) == "array" then (.result.subscriptions | length) else -1 end' <<<"${response}")"
  if [[ "${covered}" == true && "${subscriptions}" -ge 0 ]]; then
    ok "billing-coverage covered=true usage_subscriptions=${subscriptions}"
  else
    finding "billing-coverage covered=${covered} usage_subscriptions=${subscriptions}; v1 cannot prove current-period cost"
  fi
}

audit_billable_usage() {
  local account_id="$1" response total invalid metrics metric_count
  check
  response="$(cf_read --operation billing-usage-v1 --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'billing-usage the current billing-period cost inventory could not be read; zero charge is unproved'
  else
    total="$(jq -r '.result | length' <<<"${response}")"
    invalid="$(jq -r '[.result[]? |
      [.BilledCost, .ContractedCost, .CumulatedContractedCost, .EffectiveCost, .ListCost] as $costs |
      select((($costs | all(type == "number")) | not) or ($costs | any(. != 0)))
    ] | length' <<<"${response}")"
    if [[ "${invalid}" == 0 ]]; then
      ok "billing-usage all ${total} current-period record(s) have zero billed, contracted, cumulative, effective, and list cost"
    else
      finding "billing-usage ${invalid} of ${total} current-period record(s) have nonzero or missing monetary fields"
    fi
  fi

  check
  metrics="$(cf_read --operation billable-metrics --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${metrics}" ]]; then
    finding 'billable-metrics the enabled usage-billing metric inventory could not be read'
  else
    metric_count="$(jq -r '.result | length' <<<"${metrics}")"
    ok "billable-metrics complete current-period inventory count=${metric_count}; monetary verdict comes from billing-usage"
  fi
}

audit_billing_history() {
  local account_id="$1" response total positive malformed
  check
  response="$(cf_read --operation billing-history --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'billing-history the paginated invoice and payment history could not be read completely'
    return 0
  fi
  total="$(jq -r '.result | length' <<<"${response}")"
  malformed="$(jq -r '[.result[]? | select(
    ((.amount | type) != "number") or ((.amount_to_pay | type) != "number")
  )] | length' <<<"${response}")"
  positive="$(jq -r '[.result[]? | select(.amount != 0 or .amount_to_pay != 0)] | length' <<<"${response}")"
  if [[ "${malformed}" == 0 && "${positive}" == 0 ]]; then
    ok "billing-history all ${total} item(s) have amount=0 and amount_to_pay=0"
  else
    finding "billing-history nonzero_items=${positive} malformed_items=${malformed} total=${total}; zero historical charge is unproved"
  fi
}

audit_unpaid_and_debt() {
  local account_id="$1" response count positive malformed total_debt
  check
  response="$(cf_read --operation unpaid-invoices --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]] || ! jq -e '.result.invoices | type == "array"' >/dev/null 2>&1 <<<"${response}"; then
    finding 'unpaid-invoices the unpaid invoice inventory could not be read as a complete array'
  else
    count="$(jq -r '.result.invoices | length' <<<"${response}")"
    malformed="$(jq -r '[.result.invoices[]? | select(
      ((.amount | type) != "number") or ((.amount_to_pay | type) != "number")
    )] | length' <<<"${response}")"
    positive="$(jq -r '[.result.invoices[]? | select(.amount != 0 or .amount_to_pay != 0)] | length' <<<"${response}")"
    if [[ "${count}" == 0 && "${malformed}" == 0 && "${positive}" == 0 ]]; then
      ok 'unpaid-invoices none exist'
    else
      finding "unpaid-invoices count=${count} nonzero=${positive} malformed=${malformed}; zero amount due is unproved"
    fi
  fi

  check
  response="$(cf_read --operation bad-debt --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'bad-debt outstanding debt state could not be read'
    return 0
  fi
  total_debt="$(jq -r 'if (.result.total_debt_amount | type) == "number" then .result.total_debt_amount else "invalid" end' <<<"${response}")"
  if [[ "${total_debt}" == 0 ]]; then
    ok 'bad-debt total_debt_amount=0'
  else
    finding "bad-debt total_debt_amount=${total_debt}; zero outstanding debt is unproved"
  fi
}

audit_certificate_products() {
  local name="$1" zone_id="$2" response total non_universal quota allocated used
  check
  response="$(cf_read --operation certificate-packs --zone-id "${zone_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "certificate-packs[${name}] the all-status certificate inventory could not be read completely"
  else
    total="$(jq -r '.result | length' <<<"${response}")"
    non_universal="$(jq -r '[.result[]? | select(.type != "universal")] | length' <<<"${response}")"
    if [[ "${non_universal}" == 0 ]]; then
      ok "certificate-packs[${name}] all ${total} pack(s) are Universal SSL"
    else
      finding "certificate-packs[${name}] ${non_universal} of ${total} pack(s) are non-universal and may be billable"
    fi
  fi

  check
  quota="$(cf_read --operation certificate-pack-quota --zone-id "${zone_id}" 2>/dev/null || true)"
  if [[ -z "${quota}" ]]; then
    finding "certificate-quota[${name}] Advanced Certificate Manager allocation could not be read"
    return 0
  fi
  allocated="$(jq -r 'if (.result.advanced.allocated | type) == "number" then .result.advanced.allocated else "invalid" end' <<<"${quota}")"
  used="$(jq -r 'if (.result.advanced.used | type) == "number" then .result.advanced.used else "invalid" end' <<<"${quota}")"
  if [[ "${allocated}" == 0 && "${used}" == 0 ]]; then
    ok "certificate-quota[${name}] advanced allocated=0 used=0"
  else
    finding "certificate-quota[${name}] advanced allocated=${allocated} used=${used}; zero paid-certificate capacity is unproved"
  fi
}

audit_zone_plan() {
  local name="$1" zone_id="$2" zones subscription plan
  check
  zones="$(cf_read --operation zones-list --zone-name "${name}" 2>/dev/null || true)"
  if [[ -z "${zones}" ]]; then
    finding "zone-plan[${name}] the zone record could not be read"
    return 0
  fi
  plan="$(jq -r '.result[0].plan.name // "unknown"' <<<"${zones}")"
  if [[ "${plan}" =~ ^Free && "$(jq -r '.result[0].status // "unknown"' <<<"${zones}")" == active ]]; then
    ok "zone-plan[${name}] plan=${plan} status=active"
  else
    finding "zone-plan[${name}] plan=${plan} status=$(jq -r '.result[0].status // "unknown"' <<<"${zones}") expected an active Free zone"
  fi

  check
  subscription="$(cf_read --operation zone-subscription --zone-id "${zone_id}" 2>/dev/null || true)"
  if [[ -z "${subscription}" ]]; then
    finding "zone-subscription[${name}] the zone subscription could not be read"
    return 0
  fi
  if jq -e '
    ((.result.rate_plan.id // .result.rate_plan.public_name // .result.rate_plan.name // "") | test("free"; "i")) and
    (.result.price | type) == "number" and .result.price == 0 and
    ((.result.trial // false) == false) and
    (.result.rate_plan.is_contract == false) and
    (.result.rate_plan.externally_managed == false) and
    (((.result.state // "") | test("trial|awaiting"; "i")) | not)
  ' >/dev/null <<<"${subscription}"; then
    ok "zone-subscription[${name}] permanent Free plan price=0"
  else
    finding "zone-subscription[${name}] the subscription is not a permanent zero-priced Free plan"
  fi
}

audit_setting() {
  local name="$1" zone_id="$2" setting="$3" expected="$4" why="$5"
  local response value
  check
  response="$(cf_read --operation zone-setting --zone-id "${zone_id}" --setting-id "${setting}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/${setting}] could not be read; an unknown setting is not a pass"
    return 0
  fi
  value="$(jq -r '.result.value | if type == "object" then tojson else tostring end' <<<"${response}")"
  if [[ "${value}" == "${expected}" ]]; then
    ok "zone-setting[${name}/${setting}] value=${value}"
  else
    finding "zone-setting[${name}/${setting}] value=${value} expected=${expected}; ${why}"
  fi
}

audit_ssl_mode() {
  local name="$1" zone_id="$2" response value
  check
  response="$(cf_read --operation zone-setting --zone-id "${zone_id}" --setting-id ssl 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/ssl] could not be read; an unknown setting is not a pass"
    return 0
  fi
  value="$(jq -r '.result.value | tostring' <<<"${response}")"
  case "${value}" in
    full|strict)
      ok "zone-setting[${name}/ssl] value=${value}" ;;
    *)
      finding "zone-setting[${name}/ssl] value=${value} expected=full or strict; off and flexible put cleartext on the edge-to-origin leg" ;;
  esac
}

audit_managed_hsts() {
  local name="$1" zone_id="$2" response enabled enabled_type
  check
  response="$(cf_read --operation zone-setting --zone-id "${zone_id}" --setting-id security_header 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-setting[${name}/security_header] could not be read; an unknown setting is not a pass"
    return 0
  fi
  enabled_type="$(jq -r '.result.value.strict_transport_security.enabled | type' <<<"${response}")"
  enabled="$(jq -r '.result.value.strict_transport_security.enabled | tostring' <<<"${response}")"
  if [[ "${enabled_type}" == boolean && "${enabled}" == false ]]; then
    ok "zone-setting[${name}/managed-hsts] enabled=false (the application owns Strict-Transport-Security)"
  else
    finding "zone-setting[${name}/managed-hsts] enabled=${enabled} type=${enabled_type}; expected the explicit boolean false because the application owns HSTS"
  fi
}

audit_zone_settings() {
  local name="$1" zone_id="$2"
  audit_setting "${name}" "${zone_id}" always_use_https on \
    'plaintext HTTP must be redirected to HTTPS at the edge'
  audit_setting "${name}" "${zone_id}" min_tls_version 1.2 \
    'TLS 1.0 and 1.1 must be refused'
  audit_setting "${name}" "${zone_id}" tls_1_3 on \
    'TLS 1.3 must remain enabled'
  audit_setting "${name}" "${zone_id}" 0rtt off \
    'early data is replayable and stays disabled'
  audit_ssl_mode "${name}" "${zone_id}"
  audit_managed_hsts "${name}" "${zone_id}"
}

audit_dnssec() {
  local name="$1" zone_id="$2" expected="$3" response status
  check
  response="$(cf_read --operation dnssec --zone-id "${zone_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-dnssec[${name}] status could not be read"
    return 0
  fi
  status="$(jq -r '.result.status // "unknown"' <<<"${response}")"
  if [[ "${status}" == "${expected}" ]]; then
    ok "zone-dnssec[${name}] status=${status}"
  else
    finding "zone-dnssec[${name}] status=${status} expected=${expected}; if the owner ran the signing ceremony, move the recorded expectation in the same reviewed change"
  fi
}

audit_tunnels() {
  local account_id="$1" response count names
  check
  response="$(cf_read --operation tunnels-list --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding 'tunnel-inventory the Tunnel inventory could not be read completely'
    printf '%s\n' '{"result":[]}' >"${WORKDIR}/tunnels.json"
    return 1
  fi
  printf '%s\n' "${response}" >"${WORKDIR}/tunnels.json"
  count="$(jq -r '.result | length' <<<"${response}")"
  names="$(jq -r '[.result[].name] | sort | join(",")' <<<"${response}")"
  if [[ "${count}" == 2 && "${names}" == "${TUNNEL_B},${TUNNEL_A}" ]]; then
    ok "tunnel-inventory exactly the two expected per-site Tunnels exist (${names})"
  else
    finding "tunnel-inventory count=${count} names=${names} expected exactly ${TUNNEL_A} and ${TUNNEL_B}"
  fi
}

tunnel_id_for() {
  local tunnel_name="$1"
  jq -r --arg name "${tunnel_name}" \
    '[.result[]? | select(.name == $name)] | if length == 1 then (.[0].id // "") else "" end' \
    "${WORKDIR}/tunnels.json"
}

audit_tunnel_detail() {
  local account_id="$1" tunnel_name="$2" hostname="$3" origin="$4"
  local tunnel_id status config connections idle total pseudonyms connector
  check
  tunnel_id="$(tunnel_id_for "${tunnel_name}")"
  if [[ ! "${tunnel_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    finding "tunnel[${tunnel_name}] is not uniquely present with a well-formed identifier"
    return 0
  fi
  status="$(jq -r --arg name "${tunnel_name}" '.result[] | select(.name == $name) | .status // "unknown"' "${WORKDIR}/tunnels.json")"
  if [[ "${status}" == healthy ]]; then
    ok "tunnel[${tunnel_name}] id=$(redact "${tunnel_id}") status=healthy"
  else
    finding "tunnel[${tunnel_name}] id=$(redact "${tunnel_id}") status=${status} expected=healthy"
  fi

  check
  config="$(cf_read --operation tunnel-config --account-id "${account_id}" --tunnel-id "${tunnel_id}" 2>/dev/null || true)"
  if [[ -z "${config}" ]]; then
    finding "tunnel[${tunnel_name}] the ingress configuration could not be read"
  elif jq -e --arg hostname "${hostname}" --arg origin "${origin}" '
    (.result.config.ingress | type) == "array" and
    (.result.config.ingress | length) == 2 and
    .result.config.ingress[0].hostname == $hostname and
    .result.config.ingress[0].service == $origin and
    (.result.config.ingress[1] | has("hostname") | not) and
    .result.config.ingress[1].service == "http_status:404"
  ' >/dev/null <<<"${config}"; then
    ok "tunnel[${tunnel_name}] ingress is exactly one ${hostname} rule to its own origin plus the terminal 404"
  else
    finding "tunnel[${tunnel_name}] ingress is not exactly one ${hostname} rule to its own origin plus a terminal 404 rule"
  fi

  check
  connections="$(cf_read --operation tunnel-connections --account-id "${account_id}" --tunnel-id "${tunnel_id}" 2>/dev/null || true)"
  if [[ -z "${connections}" ]]; then
    finding "tunnel[${tunnel_name}] the connector inventory could not be read"
    return 0
  fi
  total="$(jq -r '.result | length' <<<"${connections}")"
  idle="$(jq -r '[.result[]? | select(((.conns // []) | length) == 0)] | length' <<<"${connections}")"
  pseudonyms=''
  while IFS= read -r connector; do
    [[ -n "${connector}" ]] || continue
    pseudonyms="${pseudonyms} $(redact "${connector}")"
  done <<<"$(jq -r '.result[]?.id // empty' <<<"${connections}")"
  printf 'RECORD tunnel[%s] connectors=%s idle=%s ids=%s\n' \
    "${tunnel_name}" "${total}" "${idle}" "${pseudonyms# }"
  if [[ "${total}" -gt 0 && "${idle}" == 0 ]]; then
    ok "tunnel[${tunnel_name}] every listed connector holds live connections"
  elif [[ "${total}" == 0 ]]; then
    finding "tunnel[${tunnel_name}] no connector is present; a vacuous idle count is not healthy"
  else
    finding "tunnel[${tunnel_name}] ${idle} connector(s) hold no live connection; check whether an old-token connector is lingering"
  fi
}

audit_no_private_network() {
  local account_id="$1" routes profiles count
  check
  routes="$(cf_read --operation private-routes --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${routes}" ]]; then
    finding 'private-routes the private-route inventory could not be read completely'
  else
    count="$(jq -r '.result | length' <<<"${routes}")"
    if [[ "${count}" == 0 ]]; then
      ok 'private-routes none exist; the two site Tunnels carry no private network surface'
    else
      finding "private-routes ${count} route(s) exist; ADR 0015 gives the site Tunnels no private or WARP routing"
    fi
  fi

  check
  profiles="$(cf_read --operation warp-profiles --account-id "${account_id}" 2>/dev/null || true)"
  if [[ -z "${profiles}" ]]; then
    # A token scoped to exactly the audited surface may legitimately lack Zero
    # Trust read permission. That is a limitation, not a pass.
    finding 'warp-profiles the device-profile inventory could not be read; confirm by hand that no WARP profile exists, or widen the audit token read scope'
  else
    count="$(jq -r '[.result[]? | select((.default // false) == false)] | length' <<<"${profiles}")"
    if [[ "${count}" == 0 ]]; then
      ok 'warp-profiles no non-default WARP device profile exists'
    else
      finding "warp-profiles ${count} non-default WARP device profile(s) exist"
    fi
  fi
}

audit_dns_records() {
  local name="$1" zone_id="$2" tunnel_id="$3"
  local response apex_count address_count unexpected
  check
  response="$(cf_read --operation dns-records --zone-id "${zone_id}" 2>/dev/null || true)"
  if [[ -z "${response}" ]]; then
    finding "zone-dns[${name}] the DNS inventory could not be read completely; a partial inventory cannot support an exactness claim"
    return 0
  fi
  address_count="$(jq -r '[.result[] | select(.type == "A" or .type == "AAAA")] | length' <<<"${response}")"
  if [[ "${address_count}" == 0 ]]; then
    ok "zone-dns[${name}] no origin A/AAAA record exists"
  else
    finding "zone-dns[${name}] ${address_count} address record(s) exist; an origin address record would publish the residential origin"
  fi

  check
  if [[ -z "${tunnel_id}" ]]; then
    finding "zone-dns[${name}] this site's Tunnel identifier is unknown, so the apex CNAME target could not be checked"
  else
    apex_count="$(jq -r --arg apex "${name}" --arg target "${tunnel_id}.cfargotunnel.com" '
      [.result[] | select(
        .name == $apex and .type == "CNAME" and .content == $target and
        .proxied == true and .ttl == 1
      )] | length' <<<"${response}")"
    if [[ "${apex_count}" == 1 ]]; then
      ok "zone-dns[${name}] exactly one proxied apex CNAME with automatic TTL targets this site's own Tunnel"
    else
      finding "zone-dns[${name}] exact_apex_cname_count=${apex_count} expected=1 (proxied, automatic TTL, this site's own Tunnel)"
    fi
  fi

  check
  unexpected="$(jq -r --arg apex "${name}" --arg target "${tunnel_id}.cfargotunnel.com" '
    [.result[] | select((
      .name == $apex and .type == "CNAME" and .content == $target and
      .proxied == true and .ttl == 1
    ) | not)] | length
  ' <<<"${response}")"
  if [[ "${unexpected}" == 0 ]]; then
    ok "zone-dns[${name}] no record beyond the apex CNAME exists"
  else
    finding "zone-dns[${name}] ${unexpected} record(s) beyond the exact apex CNAME are present; every additional name is public surface"
  fi
}

self_test() {
  local failures first second repeated schemas operation_count raw_api_literal
  failures=0
  unset CF_API_TOKEN CF_ACCOUNT_ID CF_ZONE_ID CLOUDFLARE_API_TOKEN
  unset CLOUDFLARE_API_KEY CLOUDFLARE_EMAIL CLOUDFLARE_API_USER_SERVICE_KEY
  unset CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_ZONE_ID
  resolve_tools
  printf 'cloudflare-account-audit self-test (no credential or Cloudflare account is read)\n'
  printf 'schema=%s cf_version=%s cf_executable_sha256=%s digest=%s grep=%s\n' \
    "${SCHEMA}" "${CF_VERSION}" "${CF_BIN_DIGEST}" "${DIGEST_TOOL}" "${GREP}"

  first="$(redact 'sample-identifier-one')"
  second="$(redact 'sample-identifier-one')"
  repeated="$(redact 'sample-identifier-two')"
  printf 'redaction-stable       -> %s == %s\n' "${first}" "${second}"
  [[ "${first}" == "${second}" && "${first}" == id:* ]] || failures=$(( failures + 1 ))
  printf 'redaction-distinct     -> %s != %s\n' "${first}" "${repeated}"
  [[ "${first}" != "${repeated}" ]] || failures=$(( failures + 1 ))
  printf 'redaction-hides-input  -> %s\n' "$([[ "${first}" == *sample-identifier* ]] && printf FAIL || printf ok)"
  [[ "${first}" != *sample-identifier* ]] || failures=$(( failures + 1 ))

  schemas="$(validate_cf_schemas 2>/dev/null || true)"
  if [[ -n "${schemas}" ]] && jq -e '
    .version == "v1.0.0-beta.5" and
    (.operations | type == "array" and length == 22) and
    all(.operations[]; .method == "GET" and (.path | startswith("/")))
  ' >/dev/null 2>&1 <<<"${schemas}"; then
    operation_count="$(jq -r '.operations | length' <<<"${schemas}")"
    printf 'cf-schema-read-only    -> %s operations are pinned GET requests with no body\n' "${operation_count}"
  else
    printf 'cf-schema-read-only    -> FAIL\n'
    failures=$(( failures + 1 ))
  fi
  raw_api_literal='api.cloudflare.com/''client'
  if "${GREP}" -q -F -e "${raw_api_literal}" "$0" "${CF_READER}"; then
    printf 'raw-api-absent         -> FAIL\n'
    failures=$(( failures + 1 ))
  else
    printf 'raw-api-absent         -> ok\n'
  fi
  printf 'credential-untouched   -> %s\n' "$([[ "${AUTH_READ}" == no ]] && printf ok || printf FAIL)"
  [[ "${AUTH_READ}" == no ]] || failures=$(( failures + 1 ))

  if (( failures > 0 )); then
    printf '\nRESULT schema=%s mode=self-test failures=%s exit=1\n' "${SCHEMA}" "${failures}"
    return 1
  fi
  printf '\nRESULT schema=%s mode=self-test failures=0 exit=0\n' "${SCHEMA}"
  return 0
}

run_audit() {
  local identity_a identity_b zone_a_id zone_b_id account_id account_b
  select_authentication
  resolve_tools
  validate_cf_schemas >/dev/null 2>&1 || die 'cf schema no longer matches the reviewed read-only command surface'
  umask 077
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cloudflare-account-audit.XXXXXX")"
  trap cleanup EXIT

  printf '# Cloudflare read-only account audit\n'
  printf 'schema=%s\n' "${SCHEMA}"
  printf 'generated_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'cf_version=%s\n' "${CF_VERSION}"
  printf 'cf_executable_sha256=%s\n' "${CF_BIN_DIGEST}"
  printf 'cf_auth=%s\n' "$([[ "${CF_AUTH_MODE}" == profile ]] && printf named-profile || printf api-token-env)"
  printf 'mode=%s\n' "$([[ "${RAW}" == yes ]] && printf raw || printf redacted)"
  if [[ "${RAW}" == yes ]]; then
    printf '\n!! RAW MODE: the output below contains real Cloudflare identifiers.\n'
    printf '!! It is for the owner eyes only. Never commit it, never paste it into an\n'
    printf '!! issue, pull request, comment, chat, or ticket, and delete the capture\n'
    printf '!! as soon as the review is finished.\n'
  fi
  printf '\nEvery provider request below is a cf command whose schema was verified as GET with no body. Nothing is created, updated, or deleted.\n\n'

  printf '## authentication\n'
  if ! audit_auth; then
    printf '\nRESULT schema=%s checks=%s findings=%s exit=1\n' "${SCHEMA}" "${CHECKS}" "${FINDINGS}"
    return 1
  fi

  printf '\n## zones\n'
  identity_a="$(zone_identity "${ZONE_A}" || true)"
  identity_b="$(zone_identity "${ZONE_B}" || true)"
  check
  if [[ -z "${identity_a}" || -z "${identity_b}" ]]; then
    finding 'zone-identity one or both zones did not resolve to exactly one zone; the remaining checks would be unsound'
    printf '\nRESULT schema=%s checks=%s findings=%s exit=1\n' "${SCHEMA}" "${CHECKS}" "${FINDINGS}"
    return 1
  fi
  zone_a_id="${identity_a%% *}"
  account_id="${identity_a##* }"
  zone_b_id="${identity_b%% *}"
  account_b="${identity_b##* }"
  if [[ "${account_id}" == "${account_b}" ]]; then
    ok "zone-identity account=$(redact "${account_id}") zones=$(redact "${zone_a_id}"),$(redact "${zone_b_id}")"
  else
    finding 'zone-identity the two zones live in different accounts; the account-level checks below cover only the first'
  fi

  printf '\n## zero spend\n'
  audit_account_subscriptions "${account_id}"
  audit_user_subscriptions
  audit_zone_plan "${ZONE_A}" "${zone_a_id}"
  audit_zone_plan "${ZONE_B}" "${zone_b_id}"
  audit_billing_coverage "${account_id}"
  audit_billable_usage "${account_id}"
  audit_billing_history "${account_id}"
  audit_unpaid_and_debt "${account_id}"
  audit_certificate_products "${ZONE_A}" "${zone_a_id}"
  audit_certificate_products "${ZONE_B}" "${zone_b_id}"

  printf '\n## zone settings\n'
  audit_zone_settings "${ZONE_A}" "${zone_a_id}"
  audit_zone_settings "${ZONE_B}" "${zone_b_id}"
  audit_dnssec "${ZONE_A}" "${zone_a_id}" "${DNSSEC_A}"
  audit_dnssec "${ZONE_B}" "${zone_b_id}" "${DNSSEC_B}"

  printf '\n## tunnels\n'
  audit_tunnels "${account_id}" || true
  audit_tunnel_detail "${account_id}" "${TUNNEL_A}" "${ZONE_A}" "${ORIGIN_A}"
  audit_tunnel_detail "${account_id}" "${TUNNEL_B}" "${ZONE_B}" "${ORIGIN_B}"
  audit_no_private_network "${account_id}"

  printf '\n## dns\n'
  audit_dns_records "${ZONE_A}" "${zone_a_id}" "$(tunnel_id_for "${TUNNEL_A}")"
  audit_dns_records "${ZONE_B}" "${zone_b_id}" "$(tunnel_id_for "${TUNNEL_B}")"

  printf '\n## declared evidence gaps (this audit makes no claim)\n'
  printf '%s\n' \
    '- the two Registrar renewals, identified separately from infrastructure' \
    '- account members and their passkey/MFA posture' \
    '- credentials other than the exact profile or token used for this run'

  printf '\nRESULT schema=%s checks=%s findings=%s exit=%s\n' \
    "${SCHEMA}" "${CHECKS}" "${FINDINGS}" "$(( FINDINGS > 0 ? 1 : 0 ))"
  (( FINDINGS == 0 ))
}

main() {
  local mode status
  mode=audit
  status=0
  while (( $# > 0 )); do
    case "$1" in
      --raw) RAW=yes ;;
      --self-test) mode=self-test ;;
      --profile)
        (( $# >= 2 )) || die '--profile requires a name'
        CF_PROFILE="$2"
        shift ;;
      --profile=*) CF_PROFILE="${1#--profile=}" ;;
      -h|--help) usage; return 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
  done
  if [[ "${mode}" == self-test ]]; then
    self_test || status=$?
    return "${status}"
  fi
  run_audit || status=$?
  return "${status}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
