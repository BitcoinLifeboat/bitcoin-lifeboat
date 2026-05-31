# Bitcoin Lifeboat

Bitcoin Lifeboat is not a wallet, not a custody service, not a
seed phrase manager, not an inheritance legal service, and not a
recovery company. It is a free, open-source diagnostic tool that
helps you test whether your recovery plan works.

Bitcoin Lifeboat is a local-first desktop app and CLI for rehearsing Bitcoin
self-custody recovery before a real emergency. It audits output descriptors,
derives receive/change addresses for comparison, scores recovery readiness, and
prints runbooks for owner and heir drills.

It never holds keys, never moves funds, and cannot make your funds "safe." It
helps you find gaps in a recovery plan you already have.

## The four promises

1. **We never ask for your real seed phrase.** The app has no field for entering
   a real BIP39/SLIP-39 mnemonic in normal use.
2. **We never connect to the internet without your action.** No telemetry, no
   auto-update, no remote calls by default.
3. **We never persist your wallet metadata.** Imports stay in memory; you choose
   where to export.
4. **We never claim your funds are safe.** Reports are diagnostic aids, not
   guarantees of recovery.

## What it is

- A local diagnostic for descriptor health, address comparison, readiness
  scoring, and printable recovery runbooks.
- A rehearsal tool for checking whether a self-custody recovery plan is
  understandable before it is needed.
- A Rust core plus CLI and Tauri desktop shell. Bitcoin parsing, address
  derivation, scoring, and secret detection live in Rust.

## What it is not

- Not a wallet, signer, custody service, seed phrase manager, inheritance legal
  service, or recovery company.
- Not a replacement for testing with your own signing devices and backups.
- Not an internet service. Normal flows run locally and offline.

## Status

Pre-alpha. The repository is built milestone by milestone, from the v0.1 MVP through v1.0.
The full specification lives in [`docs/PRD-v2.md`](docs/PRD-v2.md).

## Install

The toolchain is pinned: Rust 1.78 via `rust-toolchain.toml`, Node 22 via `.nvmrc`.
Pre-alpha builds are from source; signed release packages land with the release workflow.
The v0.2 packaging metadata adds Homebrew, Debian apt, and Flatpak channel files
under [`packaging/`](packaging/). Those channels still resolve to the signed
release artifacts.

Build and test the Rust workspace:

```sh
cargo build --workspace
cargo test --workspace
```

Build the CLI:

```sh
cargo build -p lifeboat --release
```

Build the desktop frontend:

```sh
cd apps/desktop
npm ci
npm run build
```

Native Tauri desktop builds need the Linux GTK/WebKit development packages listed
in [`apps/desktop/README.md`](apps/desktop/README.md). Release artifacts will be
published at `https://github.com/__GH_ORG__/bitcoin-lifeboat/releases` once the
release workflow is enabled.

## Documentation

- Product and technical docs: [`docs/README.md`](docs/README.md)
- Canonical PRD: [`docs/PRD-v2.md`](docs/PRD-v2.md)
- Public docs site: `https://bitcoinlifeboat.org/docs/`
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)

## Configuration

Deployment-specific values — GitHub org, domain, maintainer PGP key — live in
`project.config.toml`. Some ship as placeholders. See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
for what each value means and how to replace it.

## License

Code is licensed under the [MIT License](LICENSE). Documentation under `docs/` is licensed
CC-BY-SA-4.0. Contributions are accepted under the Developer Certificate of Origin (DCO) —
sign your commits with `git commit -s`. There is no CLA.
