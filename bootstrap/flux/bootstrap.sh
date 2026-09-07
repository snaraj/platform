#!/bin/bash
# Generate pinned Flux controller manifests without contacting a cluster.
builtin set -Eeuo pipefail
builtin set +x
PATH=/usr/sbin:/usr/bin:/sbin:/bin
builtin export PATH
builtin umask 077

fail() {
  builtin printf 'FAIL Flux operation made no cluster mutation.\n' >&2
  builtin exit 1
}

# Parse the requested operation before any external command or repository read.
# Live modes are retired and reject every invocation before protected reads.
mode="${1:---generate}"
[[ "$#" -le 1 ]] || fail
case "${mode}" in
  --generate) ;;
  --apply-controllers|--apply-sync|--verify)
    builtin printf 'BLOCKED Flux live modes are retired; no protected file was read and no cluster request was attempted.\n' >&2
    builtin exit 1
    ;;
  *) fail ;;
esac

# Nothing inherited may make Bash execute caller-controlled startup code,
# import a function, or interpose a dynamic loader before we establish the
# reviewed toolchain. These checks and the core limits use Bash builtins only.
while read -r function_declaration function_flag inherited_function_name; do
  [[ "${function_declaration}" == declare && "${function_flag}" == -f ]] || fail
  [[ "${inherited_function_name}" == fail ]] || fail
done < <(builtin declare -F)
for bootstrap_environment_name in $(builtin compgen -e); do
  case "${bootstrap_environment_name}" in
    BASH_ENV|ENV|BASH_FUNC_*|LD_*) fail ;;
  esac
done
builtin ulimit -S -c 0 || fail
builtin ulimit -H -c 0 || fail

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
versions_file="${repo_root}/versions.env"
controllers="${repo_root}/kubernetes/flux-system/controllers"
components="${controllers}/gotk-components.yaml"
[[ -f "${versions_file}" && ! -L "${versions_file}" ]] || fail

pin() {
  local name="$1"
  awk -F= -v key="${name}" '
    $1 == key && $2 ~ /^[A-Za-z0-9._:+@/-]+$/ { count += 1; value = $2 }
    END { if (count == 1) print value }
  ' "${versions_file}"
}
FLUX_VERSION="$(pin FLUX_VERSION)"
FLUX_LINUX_AMD64_SHA256="$(pin FLUX_LINUX_AMD64_SHA256)"
FLUX_SOURCE_CONTROLLER_IMAGE="$(pin FLUX_SOURCE_CONTROLLER_IMAGE)"
FLUX_KUSTOMIZE_CONTROLLER_IMAGE="$(pin FLUX_KUSTOMIZE_CONTROLLER_IMAGE)"
FLUX_HELM_CONTROLLER_IMAGE="$(pin FLUX_HELM_CONTROLLER_IMAGE)"
[[ "${FLUX_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail
[[ "${FLUX_LINUX_AMD64_SHA256}" =~ ^[0-9a-f]{64}$ ]] || fail
for image in "${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  "${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" "${FLUX_HELM_CONTROLLER_IMAGE}"; do
  [[ "${image}" =~ ^ghcr\.io/fluxcd/[a-z-]+:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] || fail
done

python3_binary="$(readlink -e -- /usr/bin/python3)" || fail
[[ "${python3_binary}" =~ ^/usr/bin/python3(\.[0-9]+)?$ ]] || fail
[[ -f "${python3_binary}" && ! -L "${python3_binary}" && -x "${python3_binary}" ]] || fail
[[ "$(stat -c '%u:%h' -- "${python3_binary}")" == 0:1 ]] || fail
python3_mode="$(stat -c %a -- "${python3_binary}")" || fail
(( (8#${python3_mode} & 0022) == 0 )) || fail
"${python3_binary}" -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || fail

canonical_existing_path() {
  local candidate="$1" resolved current
  [[ "${candidate}" == /* ]] || return 1
  resolved="$(readlink -e -- "${candidate}")" || return 1
  [[ "${candidate}" == "${resolved}" ]] || return 1
  current="${candidate}"
  while [[ "${current}" != / ]]; do
    [[ ! -L "${current}" ]] || return 1
    current="$(dirname -- "${current}")"
  done
}

copy_stable_file() {
  local source="$1" destination="$2" state descriptor
  canonical_existing_path "${source}" || return 1
  [[ -f "${source}" && "$(stat -c %h -- "${source}")" == 1 ]] || return 1
  state="$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" || return 1
  exec {descriptor}<"${source}" || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  command cat <&"${descriptor}" > "${destination}" || return 1
  [[ "$(stat -c '%d:%i:%f:%h:%s:%Y' -- "${source}")" == "${state}" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%f:%h:%s:%Y' -- "/proc/$$/fd/${descriptor}")" == "${state}" ]] || return 1
  exec {descriptor}<&-
}

temporary=''
cleanup() {
  if [[ -n "${temporary}" && -d "${temporary}" && ! -L "${temporary}" ]]; then
    case "${temporary}" in
      /tmp/flux-generate.*) rm -rf -- "${temporary}" ;;
      *) printf 'Refusing ambiguous Flux generation cleanup target.\n' >&2; return 1 ;;
    esac
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "${mode}" == --generate ]]; then
  : "${FLUX_BINARY:?Set the absolute verified Flux Linux AMD64 executable}"
  flux_source="${FLUX_BINARY}"
  canonical_existing_path "${flux_source}" || fail
  [[ -x "${flux_source}" && ! -L "${flux_source}" ]] || fail
  flux_mode="$(stat -c %a -- "${flux_source}")" || fail
  (( (8#${flux_mode} & 0022) == 0 )) || fail
  temporary="$(mktemp -d /tmp/flux-generate.XXXXXX)" || fail
  chmod 700 "${temporary}"
  flux="${temporary}/flux"
  generated="${temporary}/gotk-components.yaml"
  copy_stable_file "${flux_source}" "${flux}" || fail
  chmod 700 "${flux}"
  [[ "$(sha256sum -- "${flux}" | awk '{print $1}')" == "${FLUX_LINUX_AMD64_SHA256}" ]] || fail
  [[ "$("${flux}" version --client 2>/dev/null | awk '/flux:/ {print $2}')" == "${FLUX_VERSION}" ]] || fail
  "${flux}" install --version="${FLUX_VERSION}" --namespace=flux-system \
    --components=source-controller,kustomize-controller,helm-controller \
    --network-policy=true --export > "${generated}" || fail
  COMPONENTS_PATH="${generated}" \
  SOURCE_IMAGE="${FLUX_SOURCE_CONTROLLER_IMAGE}" \
  KUSTOMIZE_IMAGE="${FLUX_KUSTOMIZE_CONTROLLER_IMAGE}" \
  HELM_IMAGE="${FLUX_HELM_CONTROLLER_IMAGE}" \
    "${python3_binary}" -I - <<'PY' || fail
import os
import re
from pathlib import Path

path = Path(os.environ["COMPONENTS_PATH"])
text = path.read_text(encoding="utf-8")
for component, key in (("source", "SOURCE_IMAGE"),
                       ("kustomize", "KUSTOMIZE_IMAGE"),
                       ("helm", "HELM_IMAGE")):
    new = os.environ[key]
    prefix = "ghcr.io/fluxcd/" + component + "-controller"
    if not re.fullmatch(re.escape(prefix) + r":v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}", new):
        raise SystemExit(1)
    old = new.split("@", 1)[0]
    pattern = r"(?m)^([ \t]*image: )" + re.escape(old) + r"$"
    text, count = re.subn(pattern, lambda match: match[1] + new, text)
    if count != 1:
        raise SystemExit(1)
path.write_text(text, encoding="utf-8")
PY
  [[ "$(sha256sum -- "${flux}" | awk '{print $1}')" == "${FLUX_LINUX_AMD64_SHA256}" ]] || fail
  install -m 0644 "${generated}" "${components}" || fail
  printf 'PASS generated reviewed Flux controller desired state; no cluster or Git state changed.\n'
  exit 0
fi
