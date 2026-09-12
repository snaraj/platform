#!/usr/bin/env bash
# The ordinary job token is the sole publication credential. No App token or
# caller-selected source/tag crosses from the read-only jobs into this process.
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${RECOVERY_SELECTION:?RECOVERY_SELECTION is required}"
write_token="${GH_TOKEN}"
unset GH_TOKEN
RECOVERY_READ_TOKEN="${write_token}" python3 -I -B scripts/ci/platform_release_recovery.py verify
SOURCE_SHA="$(jq -er '.source_sha' <<<"${RECOVERY_SELECTION}")"
TAG="$(jq -er '.tag' <<<"${RECOVERY_SELECTION}")"
BASE_SHA="$(jq -er '.base_sha' <<<"${RECOVERY_SELECTION}")"
BASE_TAG="$(jq -er '.base_tag' <<<"${RECOVERY_SELECTION}")"
EXECUTION_MAIN_RUN_ID="$(jq -er '.executor_main_run_id' <<<"${RECOVERY_SELECTION}")"
EXECUTION_MAIN_RUN_ATTEMPT="$(jq -er '.executor_main_run_attempt' <<<"${RECOVERY_SELECTION}")"
MAIN_RUN_ID="$(python3 -I -B scripts/ci/platform_release_epoch.py "${TAG}" --historical-main-run)"
export SOURCE_SHA TAG BASE_SHA BASE_TAG EXECUTION_MAIN_RUN_ID EXECUTION_MAIN_RUN_ATTEMPT
GH_TOKEN="${write_token}" MAIN_RUN_ID="${MAIN_RUN_ID}" MAIN_RUN_ATTEMPT=1 \
  bash scripts/ci/publish-platform-release.sh
unset write_token
