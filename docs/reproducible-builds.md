# Reproducible Builds

Bitcoin Lifeboat treats reproducible builds as a release requirement. The
release workflow publishes `SHA256SUMS` for every artifact, signs that file, and
sets the build environment so independent builders can compare their local
artifacts with the published hashes.

## What Is Pinned

- Root Rust workspace: `rust-toolchain.toml` pins Rust 1.78.0.
- Tauri Rust workspace: `apps/desktop/src-tauri/rust-toolchain.toml` pins Rust 1.86.0.
- Node: `.nvmrc` pins Node 22.
- Rust dependencies: committed `Cargo.lock` files.
- Desktop dependencies: `apps/desktop/package-lock.json`.
- Build metadata: `SOURCE_DATE_EPOCH` is the commit timestamp from `git log -1 --format=%ct`.

## Deterministic Environment

The release workflow and local helper script export the same core settings:

```sh
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME=~"
```

`SOURCE_DATE_EPOCH` removes wall-clock timestamps from tools that honor it.
`--remap-path-prefix` strips local checkout paths from Rust debug and panic
metadata. `CARGO_INCREMENTAL=0` keeps release builds from depending on local
incremental state.

## Build The Tauri Bundle

Use the reproducible Tauri wrapper from the repository root:

```sh
scripts/reproducible-tauri-build.sh --target x86_64-unknown-linux-gnu --bundles appimage,deb
```

The script reads the commit timestamp, exports the deterministic Rust settings,
runs `npm ci`, builds the frontend, and then runs the pinned Tauri CLI. On Linux
you still need the GTK/WebKit packages listed in `apps/desktop/README.md`.

## Demonstrate Two Builds

The demo script builds from two separate archived checkouts and compares the
bundle hashes:

```sh
scripts/demo-reproducible-tauri-build.sh --target x86_64-unknown-linux-gnu --bundles appimage,deb
```

It exits 0 only when both build directories produce byte-identical bundle files.
If a platform packager embeds host-specific metadata, the diff names the file so
the release can be fixed before publishing.

## Verify A Local Build

After building or downloading artifacts, place the release `SHA256SUMS` beside
them and run:

```sh
lifeboat verify-build v0.1.0 --artifact bitcoin-lifeboat-v0.1.0-linux-x86_64.AppImage
```

With no `--artifact`, the command checks local files in the current directory
whose names appear in `SHA256SUMS`. With no local `SHA256SUMS`, it fetches the
file from the configured GitHub Release URL for the version you supplied.

JSON output is available:

```sh
lifeboat --json verify-build v0.1.0 --artifact bitcoin-lifeboat-v0.1.0-source.tar.gz
```

Exit code 0 means every checked artifact matched. Exit code 2 means at least one
artifact differed or had no published hash. File and argument errors use the
standard CLI exit-code table.

## Release Workflow

`.github/workflows/release.yml` uses the same deterministic settings for the
root quality gate, CLI release binaries, and Tauri desktop bundles. The publish
job gathers artifacts, writes `SHA256SUMS`, signs each artifact and checksum file
with minisign, adds cosign bundles, and publishes SLSA provenance.

Before any release job builds artifacts, `scripts/verify-release-gates.sh` checks
the tag. Alpha and beta tags may proceed with the visible pre-release banner.
Public non-alpha/beta tags require a completed security-audit sign-off and no
configured placeholder tokens in tracked files. See
[Security audit](security-audit.md) for the sign-off format.

The release notes include the minisign public key. Users should verify the
signed checksum file before trusting any artifact:

```sh
minisign -V -P '<minisign-public-key-from-release-notes>' -m SHA256SUMS -x SHA256SUMS.minisig
sha256sum --check SHA256SUMS
```

## Known Limits

Desktop package formats can still include platform-specific metadata from Apple,
Windows, AppImage, or Debian tooling. Those formats are built through the
deterministic wrapper and checked by the two-build demo, but any platform drift
must be fixed in the release branch before a public release.

Alpha and beta builds may still contain placeholder project metadata from
`project.config.toml`. Public non-alpha/beta releases are blocked until those
placeholders are replaced.
