#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage_dir="${1:-${repo_root}/target/packaging/channels}"

homebrew_formula="${repo_root}/packaging/homebrew/bitcoin-lifeboat.rb"
debian_sources="${repo_root}/packaging/debian/bitcoin-lifeboat.sources"
flatpak_manifest="${repo_root}/packaging/flatpak/org.bitcoinlifeboat.BitcoinLifeboat.json"

rm -rf "${stage_dir}"
mkdir -p \
  "${stage_dir}/homebrew/Formula" \
  "${stage_dir}/apt/dists/stable/main/binary-amd64" \
  "${stage_dir}/flatpak"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "${homebrew_formula}" >/dev/null
else
  grep -q '^class BitcoinLifeboat < Formula$' "${homebrew_formula}"
  grep -q '^  def install$' "${homebrew_formula}"
  grep -q '^  test do$' "${homebrew_formula}"
  grep -q '^end$' "${homebrew_formula}"
fi
python3 -m json.tool "${flatpak_manifest}" > "${stage_dir}/flatpak/org.bitcoinlifeboat.BitcoinLifeboat.pretty.json"

grep -q '^Types: deb$' "${debian_sources}"
grep -q '^URIs: https://bitcoinlifeboat.org/apt$' "${debian_sources}"
grep -q '^Suites: stable$' "${debian_sources}"
grep -q '^Components: main$' "${debian_sources}"
grep -q '^Architectures: amd64$' "${debian_sources}"
grep -q '^Signed-By: /usr/share/keyrings/bitcoin-lifeboat-archive-keyring.gpg$' "${debian_sources}"

install -Dm644 "${homebrew_formula}" "${stage_dir}/homebrew/Formula/bitcoin-lifeboat.rb"
install -Dm644 "${debian_sources}" "${stage_dir}/apt/bitcoin-lifeboat.sources"
install -Dm644 "${flatpak_manifest}" "${stage_dir}/flatpak/org.bitcoinlifeboat.BitcoinLifeboat.json"

cat > "${stage_dir}/apt/dists/stable/Release" <<'RELEASE'
Origin: Bitcoin Lifeboat
Label: Bitcoin Lifeboat
Suite: stable
Codename: stable
Architectures: amd64
Components: main
Description: Bitcoin Lifeboat Debian packages
RELEASE

cat > "${stage_dir}/apt/dists/stable/main/binary-amd64/Packages" <<'PACKAGES'
Package: bitcoin-lifeboat
Version: 0.2.0-alpha.1
Architecture: amd64
Maintainer: Bitcoin Lifeboat Contributors
Filename: pool/main/b/bitcoin-lifeboat/bitcoin-lifeboat_0.2.0-alpha.1_amd64.deb
Description: local-first Bitcoin recovery readiness app and CLI
PACKAGES

echo "Packaging metadata staged at ${stage_dir}"
