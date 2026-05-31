#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo_root}" log -1 --format=%ct)}"
work_root="${TMPDIR:-/tmp}/bitcoin-lifeboat-repro-${source_date_epoch}-$$"

cleanup() {
  rm -rf "${work_root}"
}
trap cleanup EXIT

mkdir -p "${work_root}/a" "${work_root}/b"

for build_id in a b; do
  mkdir -p "${work_root}/${build_id}/src"
  git -C "${repo_root}" archive --format=tar HEAD | tar -x -C "${work_root}/${build_id}/src"
  (
    cd "${work_root}/${build_id}/src"
    SOURCE_DATE_EPOCH="${source_date_epoch}" scripts/reproducible-tauri-build.sh "$@"
  )
  bundle_root="${work_root}/${build_id}/src/apps/desktop/src-tauri/target"
  find "${bundle_root}" -path '*/release/bundle/*' -type f -print0 \
    | sort -z \
    | while IFS= read -r -d '' artifact; do
        rel="${artifact#${bundle_root}/}"
        sha256sum "${artifact}" | sed "s#  .*#  ${rel}#"
      done > "${work_root}/${build_id}/SHA256SUMS.local"
  if [[ ! -s "${work_root}/${build_id}/SHA256SUMS.local" ]]; then
    echo "No Tauri bundle artifacts found under ${bundle_root}" >&2
    exit 1
  fi
done

if diff -u "${work_root}/a/SHA256SUMS.local" "${work_root}/b/SHA256SUMS.local"; then
  echo "Two independent Tauri builds produced byte-identical bundle artifacts."
else
  echo "Tauri bundle artifacts differed between independent builds." >&2
  exit 1
fi
