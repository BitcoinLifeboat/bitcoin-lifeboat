# Download and Verify Signatures

Bitcoin Lifeboat releases are meant to be checked before you run them. The checks do two things: confirm that the file matches the published checksums, and confirm that the checksum file was signed by the release key.

Alpha and beta releases may use placeholder project metadata until the public
release gate replaces it. Check `project.config.toml` in the source tree for the
configured GitHub repository, public site domain, and maintainer PGP fingerprint.
Stable releases are blocked until the external audit sign-off is recorded in
[Security audit](security-audit.md).

## Download From Official Channels

Use the release page for the configured GitHub repository:

```text
project.config.toml -> github.url_base
```

Do not use a download link sent by a stranger, a search ad, or an account that contacted you first. If you are unsure, compare the link against the source tree and the public docs domain before downloading.

## What Each Release Publishes

Each GitHub Release should include:

- Installers for macOS, Windows, and Linux.
- CLI archives for each supported platform.
- Homebrew, Debian apt, and Flatpak channel metadata for v0.2 and later.
- A source tarball.
- `SHA256SUMS`.
- `SHA256SUMS.minisig`.
- SPDX and CycloneDX SBOM files.
- cosign keyless signature bundles and SLSA provenance.
- Release notes showing the minisign public key used for that release.

macOS and Windows installers may be labeled `OS-unsigned` on alpha or beta builds when paid Apple or Windows signing secrets are not configured yet. Those builds are still minisign-signed and cosign-signed.

## Package Manager Channels

Homebrew, apt, and Flatpak metadata point back to the same signed release
artifacts. Treat them as install conveniences, not a replacement for checking
the release identity and checksums.

For alpha builds, package metadata can still contain placeholder repository or
checksum values. Use the GitHub Release assets directly until the published
channel has real checksums and the expected signing key.

## Verify With Minisign

Install minisign, download `SHA256SUMS`, `SHA256SUMS.minisig`, and the installer or archive you plan to run, then copy the minisign public key from the GitHub Release notes.

Verify the checksum file:

```sh
minisign -V -P '<minisign-public-key-from-release-notes>' -m SHA256SUMS -x SHA256SUMS.minisig
```

Then verify the downloaded artifact against the signed checksums:

```sh
sha256sum --check SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS` if `sha256sum` is not installed.

If you built an artifact locally and want to compare it with the published
release hashes, use the CLI verifier:

```sh
lifeboat verify-build v0.1.0 --artifact bitcoin-lifeboat-v0.1.0-linux-x86_64.AppImage
```

Run it in the directory containing `SHA256SUMS`, or let it fetch the checksum
file from the configured release URL for the version you supplied.

## Check Cosign Provenance

Each artifact also has a cosign keyless bundle. The release workflow publishes SLSA provenance through GitHub Actions OIDC, so auditors can check that the artifact came from the release workflow for this repository.

For a downloaded artifact:

```sh
cosign verify-blob \
  --bundle bitcoin-lifeboat-v0.1.0-linux-x86_64.AppImage.sigstore.json \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  bitcoin-lifeboat-v0.1.0-linux-x86_64.AppImage
```

Use the matching filename and tag from the release you downloaded.

## If Verification Fails

Do not run the installer. Delete the downloaded file, download again from the official release page, and repeat the check.

If the failure repeats, report it through the security contact listed in `project.config.toml` and `SECURITY.md`. Include the filename, checksum, release URL, operating system, and the exact verification command output. Do not include seed words, private keys, passphrases, or wallet descriptors in the report.

## Offline Installers

For high-value setups, download and verify on a machine you already trust, then move the verified installer using removable media. Keep the checksum and signature files with the installer so the same artifact can be checked again later.
