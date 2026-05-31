#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_tauri_dir="${repo_root}/apps/desktop/src-tauri"
hwi_version="3.2.0"
target_triple=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/install-hwi-sidecar.sh --target TARGET_TRIPLE

Downloads the official Bitcoin Core HWI release artifact, verifies pinned
SHA256 checksums, and installs it using Tauri's required sidecar filename:

  apps/desktop/src-tauri/binaries/hwi-lifeboat-<target-triple>[.exe]

Supported targets:
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  universal-apple-darwin
  x86_64-pc-windows-msvc
USAGE
}

die() {
  echo "HWI sidecar install failed: $*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

check_sha256() {
  local file="$1"
  local expected="$2"
  local actual
  actual="$(sha256_file "${file}")"
  [[ "${actual}" == "${expected}" ]] || die "$(basename "${file}") sha256 mismatch: expected ${expected}, got ${actual}"
}

download() {
  local asset="$1"
  local output="$2"
  curl -fsSL "https://github.com/bitcoin-core/HWI/releases/download/${hwi_version}/${asset}" -o "${output}"
}

extract_tar_hwi() {
  local archive="$1"
  local output="$2"
  tar -xzf "${archive}" -C "$(dirname "${output}")" hwi
  mv "$(dirname "${output}")/hwi" "${output}"
}

extract_zip_hwi() {
  local archive="$1"
  local output="$2"
  python3 - "${archive}" "${output}" <<'PY'
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
output = Path(sys.argv[2])
with zipfile.ZipFile(archive) as zf:
    with zf.open("hwi.exe") as src:
        output.write_bytes(src.read())
PY
}

install_one() {
  local asset="$1"
  local archive_sha="$2"
  local inner_sha="$3"
  local output="$4"
  local tmp="$5"
  local archive="${tmp}/${asset}"
  local extracted="${tmp}/hwi-extracted"

  download "${asset}" "${archive}"
  check_sha256 "${archive}" "${archive_sha}"

  case "${asset}" in
    *.tar.gz) extract_tar_hwi "${archive}" "${extracted}" ;;
    *.zip) extract_zip_hwi "${archive}" "${extracted}" ;;
    *) die "unsupported HWI archive type: ${asset}" ;;
  esac

  check_sha256 "${extracted}" "${inner_sha}"
  install -m 0755 "${extracted}" "${output}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || die "--target requires a value"
      target_triple="$2"
      shift 2
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

[[ -n "${target_triple}" ]] || die "--target is required"
need_command curl
need_command python3

mkdir -p "${src_tauri_dir}/binaries"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

case "${target_triple}" in
  x86_64-unknown-linux-gnu)
    install_one \
      "hwi-${hwi_version}-linux-x86_64.tar.gz" \
      "3787c791fac7380a9f23a8815e4381ddc50911e70220c5a37ee8c013ea0287cd" \
      "d9cc65de95e3cf93fd3c953d589184a00180624ffc5ad17aade97616a8919fa6" \
      "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}" \
      "${tmp}"
    ;;
  aarch64-unknown-linux-gnu)
    install_one \
      "hwi-${hwi_version}-linux-aarch64.tar.gz" \
      "8cc8280f687f4ecba7ea805a33636c11d0a31ae2e19f1cafd3acee8204884afd" \
      "c2117b96d318be0ceac217098933834ef88376c704ca9fadacd83c9471066dcc" \
      "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}" \
      "${tmp}"
    ;;
  x86_64-apple-darwin)
    install_one \
      "hwi-${hwi_version}-mac-x86_64.tar.gz" \
      "a8f659ef5d51d0b00dc4dd95f32c9125769515cb2716ffc049717f37fb310107" \
      "b3764a530b635e7a7348c9185e09e74b389f5f585094fe316f700eec7c761875" \
      "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}" \
      "${tmp}"
    ;;
  aarch64-apple-darwin)
    install_one \
      "hwi-${hwi_version}-mac-arm64.tar.gz" \
      "dd1e1c37dc9c1d3f4ba63dd1e50c0b360828090ad1b97b4e1c805ef043691d31" \
      "87a8991848a0216213ddf6497c753cebbda492626afaf5608c30931155c922c3" \
      "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}" \
      "${tmp}"
    ;;
  universal-apple-darwin)
    need_command lipo
    x86="${tmp}/hwi-x86_64"
    arm="${tmp}/hwi-aarch64"
    install_one \
      "hwi-${hwi_version}-mac-x86_64.tar.gz" \
      "a8f659ef5d51d0b00dc4dd95f32c9125769515cb2716ffc049717f37fb310107" \
      "b3764a530b635e7a7348c9185e09e74b389f5f585094fe316f700eec7c761875" \
      "${x86}" \
      "${tmp}"
    install_one \
      "hwi-${hwi_version}-mac-arm64.tar.gz" \
      "dd1e1c37dc9c1d3f4ba63dd1e50c0b360828090ad1b97b4e1c805ef043691d31" \
      "87a8991848a0216213ddf6497c753cebbda492626afaf5608c30931155c922c3" \
      "${arm}" \
      "${tmp}"
    lipo -create "${x86}" "${arm}" -output "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}"
    chmod 0755 "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}"
    ;;
  x86_64-pc-windows-msvc)
    install_one \
      "hwi-${hwi_version}-windows-x86_64.zip" \
      "2f1a5574647e3ce11b1a05feab2fcbbf17061937c970d321d7f4c28a7b6eca23" \
      "e068d91b664597425a8ead02d7b86a02ad6c4b72746c42961f58a58b08f9fd79" \
      "${src_tauri_dir}/binaries/hwi-lifeboat-${target_triple}.exe" \
      "${tmp}"
    ;;
  *)
    usage >&2
    die "unsupported target: ${target_triple}"
    ;;
esac

"${repo_root}/scripts/verify-hwi-sidecar.sh" --target "${target_triple}"
