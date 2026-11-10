#!/usr/bin/env bash
# Scan the pinned obsync TLS proxy image for HIGH and CRITICAL vulnerabilities
# on both runtime platforms. Pull-request and main CI run this only when the
# change touches what defines or scans the image (proxy_image_scan_scope.py);
# scheduled-security.yml runs it unconditionally on main, so a CVE published
# against the unchanged pin is still found without failing unrelated changes.
# Run from the repository root.
set -euo pipefail
proxy_image="$(sed -n 's/^OBSYNC_TLS_PROXY_IMAGE=//p' versions.env)"
[[ "$proxy_image" =~ ^docker\.io/nginx/nginx-unprivileged:[a-z0-9.-]+@sha256:[0-9a-f]{64}$ ]]
docker_config="$(mktemp -d "${RUNNER_TEMP}/proxy-scan-config.XXXXXX")"
for platform in linux/amd64 linux/arm64; do
  DOCKER_CONFIG="$docker_config" trivy image --image-src remote --platform "$platform" \
    --exit-code 1 --scanners vuln --severity HIGH,CRITICAL "$proxy_image"
done
