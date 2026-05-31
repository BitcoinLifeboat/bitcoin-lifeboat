#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
desktop_dir="${repo_root}/apps/desktop"

target_triple=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --target)
      if ((i + 1 < ${#args[@]})); then
        target_triple="${args[$((i + 1))]}"
      fi
      ;;
    --target=*)
      target_triple="${args[$i]#--target=}"
      ;;
  esac
done
if [[ -z "${target_triple}" ]]; then
  if rustc --print host-tuple >/dev/null 2>&1; then
    target_triple="$(rustc --print host-tuple)"
  else
    target_triple="$(rustc -Vv | awk '/^host:/ { print $2; exit }')"
  fi
fi

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo_root}" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH="${source_date_epoch}"
export CARGO_INCREMENTAL=0

remap_flags=(
  "--remap-path-prefix=${repo_root}=."
  "--remap-path-prefix=${CARGO_HOME:-${HOME}/.cargo}=/cargo-home"
)
if [[ -n "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS} ${remap_flags[*]}"
else
  export RUSTFLAGS="${remap_flags[*]}"
fi

export NPM_CONFIG_AUDIT=false
export NPM_CONFIG_FUND=false

echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
echo "RUSTFLAGS=${RUSTFLAGS}"
echo "desktop rust toolchain: $(sed -n 's/^channel = \"\\(.*\\)\"/\\1/p' "${desktop_dir}/src-tauri/rust-toolchain.toml")"
echo "node version pin: $(tr -d '[:space:]' < "${repo_root}/.nvmrc")"
echo "tauri target: ${target_triple}"

"${repo_root}/scripts/check-native-desktop-deps.sh"
"${repo_root}/scripts/verify-hwi-sidecar.sh" --target "${target_triple}"

cd "${desktop_dir}"
npm ci
npm run build
npm run tauri -- build "$@"
