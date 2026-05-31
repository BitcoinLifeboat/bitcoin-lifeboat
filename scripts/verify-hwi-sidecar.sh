#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_tauri_dir="${repo_root}/apps/desktop/src-tauri"
target_triple=""
min_version="3.2.0"
require_runnable="auto"

usage() {
  cat <<'USAGE'
Usage:
  scripts/verify-hwi-sidecar.sh [--target TARGET_TRIPLE] [--min-version 3.2.0]

Checks that the Tauri HWI sidecar exists at the target-specific filename required
by bundle.externalBin. For example:

  apps/desktop/src-tauri/binaries/hwi-lifeboat-x86_64-unknown-linux-gnu
  apps/desktop/src-tauri/binaries/hwi-lifeboat-aarch64-apple-darwin
  apps/desktop/src-tauri/binaries/hwi-lifeboat-x86_64-pc-windows-msvc.exe

Options:
  --target TARGET_TRIPLE   Target triple to check. Defaults to the host triple.
  --min-version VERSION    Minimum accepted HWI version. Defaults to 3.2.0.
  --require-runnable       Require executing the sidecar and checking --version.
  --no-require-runnable    Only check path/executable metadata.
USAGE
}

die() {
  echo "HWI sidecar check failed: $*" >&2
  exit 1
}

host_triple() {
  if rustc --print host-tuple >/dev/null 2>&1; then
    rustc --print host-tuple
  else
    rustc -Vv | awk '/^host:/ { print $2; exit }'
  fi
}

version_ge() {
  local actual="$1"
  local required="$2"
  local actual_major actual_minor actual_patch required_major required_minor required_patch
  IFS=. read -r actual_major actual_minor actual_patch <<<"${actual}"
  IFS=. read -r required_major required_minor required_patch <<<"${required}"
  actual_patch="${actual_patch:-0}"
  required_patch="${required_patch:-0}"

  if ((actual_major != required_major)); then
    ((actual_major > required_major))
    return
  fi
  if ((actual_minor != required_minor)); then
    ((actual_minor > required_minor))
    return
  fi
  ((actual_patch >= required_patch))
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || die "--target requires a value"
      target_triple="$2"
      shift 2
      ;;
    --min-version)
      [[ $# -ge 2 ]] || die "--min-version requires a value"
      min_version="$2"
      shift 2
      ;;
    --require-runnable)
      require_runnable="yes"
      shift
      ;;
    --no-require-runnable)
      require_runnable="no"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ "${min_version}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "invalid --min-version: ${min_version}"

if [[ -z "${target_triple}" ]]; then
  target_triple="$(host_triple)"
fi
[[ -n "${target_triple}" ]] || die "could not determine target triple"

extension=""
case "${target_triple}" in
  *windows*|*pc-windows*) extension=".exe" ;;
esac

sidecar="${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}${extension}"
[[ -f "${sidecar}" ]] || die "missing ${sidecar}"

if [[ "${extension}" != ".exe" && ! -x "${sidecar}" ]]; then
  die "${sidecar} is not executable"
fi

current_host="$(host_triple)"
if [[ "${require_runnable}" == "auto" ]]; then
  if [[ "${target_triple}" == "${current_host}" || "${target_triple}" == "universal-apple-darwin" && "${current_host}" == *"apple-darwin" ]]; then
    require_runnable="yes"
  else
    require_runnable="no"
  fi
fi

if [[ "${require_runnable}" == "yes" ]]; then
  version_output="$("${sidecar}" --version 2>&1)" || die "${sidecar} --version failed"
  actual_version="$(printf '%s\n' "${version_output}" | grep -Eo '[0-9]+(\.[0-9]+){1,2}' | tail -n 1)"
  [[ -n "${actual_version}" ]] || die "could not parse HWI version from: ${version_output}"
  if ! version_ge "${actual_version}" "${min_version}"; then
    die "HWI ${actual_version} is older than required ${min_version}"
  fi
  echo "HWI sidecar check passed: ${sidecar} reports ${actual_version}."
else
  echo "HWI sidecar file check passed: ${sidecar}."
fi
