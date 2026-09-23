#!/usr/bin/env bash
# Drain EVERY pending edge of one canonical selection, in ledger order, inside
# one dispatch (issue #395). The ordinary job token is the sole publication
# credential: no App token and no caller-selected source or tag crosses from
# the read-only jobs into this process. The first refusal stops the run and
# nothing after it is attempted, so a stopped drain leaves a prefix of the
# backlog published and the rest exactly as it was.
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${RECOVERY_SELECTION:?RECOVERY_SELECTION is required}"
write_token="${GH_TOKEN}"
unset GH_TOKEN
RECOVERY_READ_TOKEN="${write_token}" python3 -I -B scripts/ci/platform_release_recovery.py verify

pending="$(jq -er '.edges | length | select(. > 0)' <<<"${RECOVERY_SELECTION}")"
EXECUTION_MAIN_RUN_ID="$(jq -er '.executor_main_run_id' <<<"${RECOVERY_SELECTION}")"
EXECUTION_MAIN_RUN_ATTEMPT="$(jq -er '.executor_main_run_attempt' <<<"${RECOVERY_SELECTION}")"
export EXECUTION_MAIN_RUN_ID EXECUTION_MAIN_RUN_ATTEMPT

published=0
# One refusal shape for both halves of an edge, so neither can fail quietly.
stop() {
  printf 'RECOVERY_EDGE tag=%s source=%s seconds=%s decision=refused:%s\n' \
    "${TAG}" "${SOURCE_SHA}" "$2" "$1" >&2
  printf 'RECOVERY_SUMMARY pending=%s published=%s stopped_at=%s seconds=%s\n' \
    "${pending}" "${published}" "${TAG}" "${SECONDS}" >&2
}

for index in $(seq 0 $((pending - 1))); do
  edge="$(jq -ecr --argjson index "${index}" '.edges[$index]' <<<"${RECOVERY_SELECTION}")"
  SOURCE_SHA="$(jq -er '.source_sha' <<<"${edge}")"
  TAG="$(jq -er '.tag' <<<"${edge}")"
  BASE_SHA="$(jq -er '.base_sha' <<<"${edge}")"
  BASE_TAG="$(jq -er '.base_tag' <<<"${edge}")"
  MAIN_RUN_ID="$(jq -er '.main_run_id' <<<"${edge}")"
  MAIN_RUN_ATTEMPT="$(jq -er '.main_run_attempt' <<<"${edge}")"
  RECOVERY_EDGE_TAG="${TAG}"
  export SOURCE_SHA TAG BASE_SHA BASE_TAG RECOVERY_EDGE_TAG
  edge_started="${SECONDS}"
  # `prove_context`'s executor-equals-current-main check runs inside every
  # write boundary, so a merge landing mid-drain stops the loop at the next
  # edge instead of publishing against a main the executor no longer is.
  # `if ! cmd` would reset $? to zero inside the branch, so the exit status is
  # captured on the failing command itself and carried out of the loop intact.
  status=0
  GH_TOKEN="${write_token}" MAIN_RUN_ID="${MAIN_RUN_ID}" \
    MAIN_RUN_ATTEMPT="${MAIN_RUN_ATTEMPT}" \
    bash scripts/ci/publish-platform-release.sh || status="$?"
  if [ "${status}" != 0 ]; then
    stop "publisher-exit-${status}" "$((SECONDS - edge_started))"
    exit "${status}"
  fi
  status=0
  RECOVERY_READ_TOKEN="${write_token}" \
    python3 -I -B scripts/ci/platform_release_recovery.py readback || status="$?"
  if [ "${status}" != 0 ]; then
    stop "readback-exit-${status}" "$((SECONDS - edge_started))"
    exit "${status}"
  fi
  published=$((published + 1))
  printf 'RECOVERY_EDGE tag=%s source=%s seconds=%s decision=published\n' \
    "${TAG}" "${SOURCE_SHA}" "$((SECONDS - edge_started))"
done

printf 'RECOVERY_SUMMARY pending=%s published=%s stopped_at=none seconds=%s\n' \
  "${pending}" "${published}" "${SECONDS}"
test "${published}" = "${pending}"
unset write_token
