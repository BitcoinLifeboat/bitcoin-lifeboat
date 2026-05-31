# Developer Guide

Bitcoin Lifeboat is split into Rust core crates, a CLI, a Tauri desktop shell, and this static docs site. The rule of thumb is simple: Bitcoin logic belongs in Rust, and presentation code asks Rust for typed results.

## Build From Source

Use the pinned toolchains:

```sh
rustup toolchain install 1.78.0 --component clippy rustfmt
nvm use
cargo build --workspace
```

The desktop app has its own Tauri Rust workspace under `apps/desktop/src-tauri` with a newer local toolchain. Native desktop builds need the GTK/WebKit development packages listed in `apps/desktop/README.md`.

## Core Quality Gates

Run these from the repository root for Rust stories:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run these from `apps/desktop` for desktop UI stories:

```sh
npm run typecheck
npm test
npm run build
npm run verify:security
```

Run these from `apps/docs-site` for docs-site stories:

```sh
npm run typecheck
npm run build
```

Run the release-gate fixture tests after changing release scripts, project
configuration, or audit docs:

```sh
scripts/verify-release-gates.sh --self-test
```

## Add A Fixture

Fixtures live under the repository root `fixtures/` directory, not inside individual crates. Use deterministic testnet or regtest data. Do not commit real wallet metadata.

Rust tests should load fixtures with `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/", "..."))` so paths remain stable across crates.

## Add Wallet Compatibility

1. Add a redacted fixture under `fixtures/wallet_exports/`.
2. Implement parsing in `crates/wallet-imports`.
3. Normalize the export into descriptors, origin metadata, and birth hints.
4. Add unit tests and golden coverage.
5. Update [wallet compatibility](wallet-compatibility.md) with the wallet version, export path, limits, and tier.

The importer must not decode or process private keys, seed material, or passphrases.

## Add A Runbook Template

Runbook templates belong in `crates/runbook-engine`. Templates may include wallet summary data, signer tables, blank fields, and instructions. They must not require users to type seed words or passphrases into the app.

Add snapshot or hash tests for public-safe and private modes when the output is deterministic.

## Docs Site

The docs site is generated from Markdown under `docs/`. Edit the root docs first, then run:

```sh
cd apps/docs-site
npm run sync
npm run build
```

Do not edit generated files under `apps/docs-site/src/content/docs/`.
