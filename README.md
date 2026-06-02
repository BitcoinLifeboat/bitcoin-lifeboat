# Bitcoin Lifeboat

**Practice losing your bitcoin before it happens.**

Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase
manager, not an inheritance legal service, and not a recovery company. It is a
free, open-source diagnostic tool that helps you test whether your recovery
plan works.

Bitcoin has a self-custody adoption problem: people are told to back up their
seed phrase, then most never prove the backup can actually recover the wallet.
Experts can work around that gap. Families, heirs, small businesses, and
ordinary savers need a way to rehearse failure before one mistake becomes
permanent loss.

The next adoption narrative is recovery confidence. Bitcoin Lifeboat makes
recovery rehearsal normal. The thesis is simple:

> Not your keys, not your coins. Not tested, not recoverable.

## What Lifeboat Does

Bitcoin Lifeboat is a local-first desktop app and CLI for rehearsing Bitcoin
self-custody recovery before a real emergency.

It can:

- Audit output descriptors and wallet metadata for recovery-critical gaps.
- Derive receive and change addresses so you can compare them with addresses you
  already recognize.
- Score recovery readiness without pretending a score is a guarantee.
- Generate public-safe reports and printable runbooks for owner and heir drills.
- Help wallet developers, educators, and meetup organizers test recovery flows
  with deterministic fixtures instead of real wallet material.

It never holds keys, never moves funds, and cannot make your funds safe. It
helps you find gaps in a recovery plan you already have.

## Why This Matters

Bitcoin adoption depends on more than buying, saving, and holding. People need
to know they can recover after a lost laptop, dead hardware wallet, missing
coordinator file, forgotten derivation path, estate transition, or multisig
signer failure.

The culture already has a powerful norm: **not your keys, not your coins**.
Lifeboat adds the next one: **run the drill**.

The goal is not to make self-custody effortless. The goal is to make it
rehearsable, legible, and honest about what the tool can and cannot prove.

## The Four Promises

1. **We never ask for your real seed phrase.** The app has no field for entering
   a real BIP39/SLIP-39 mnemonic in normal use.
2. **We never connect to the internet without your action.** No telemetry, no
   auto-update, no remote calls by default.
3. **We never persist your wallet metadata.** Imports stay in memory; you choose
   where to export.
4. **We never claim your funds are safe.** Reports are diagnostic aids, not
   guarantees of recovery.

These are implementation rules, not slogans. They shape the app design, CLI
behavior, exports, docs, tests, and release gates.

## Who It Is For

- Bitcoiners who manage singlesig, multisig, or inheritance instructions.
- Families and trusted helpers who need a recovery plan they can understand
  before stress, grief, or urgency enter the picture.
- Wallet teams that want deterministic checks for descriptor exports, address
  matching, and recovery documentation.
- Educators, meetups, and security reviewers teaching self-custody with testnet,
  signet, or regtest material.
- Builders who believe Bitcoin should normalize recovery drills the way it
  normalized hardware wallets and multisig.

## What It Is Not

- Not a wallet, signer, custody service, seed phrase manager, inheritance legal
  service, or recovery company.
- Not a replacement for testing with your own signing devices and backups.
- Not an internet service. Normal flows run locally and offline.
- Not a promise that your recovery plan is complete. It can only check the
  scenarios and material you provide.

## Status

Pre-alpha. The repository is moving milestone by milestone from the v0.1 MVP
toward v1.0. The MVP centers on descriptor audit, readiness reporting, printable
runbooks, and a first-class CLI. Signet drills, PSBT rehearsal, hardware-wallet
flows, and richer heir drills arrive in later milestones.

The canonical specification lives in [`docs/PRD-v2.md`](docs/PRD-v2.md).

## Quick Start

The toolchain is pinned: Rust 1.78 via `rust-toolchain.toml`, Node 22 via
`.nvmrc`. Pre-alpha builds are from source; signed release packages land with
the release workflow.

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

Native Tauri desktop builds need the Linux GTK/WebKit development packages
listed in [`apps/desktop/README.md`](apps/desktop/README.md).

## Project Links

- Public repository: <https://github.com/BitcoinLifeboat/bitcoin-lifeboat>
- Releases: <https://github.com/BitcoinLifeboat/bitcoin-lifeboat/releases>
- Public docs site: <https://bitcoinlifeboat.org/docs/>
- Product and technical docs: [`docs/README.md`](docs/README.md)
- Canonical PRD: [`docs/PRD-v2.md`](docs/PRD-v2.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)

## How To Help

The most useful contributions right now are practical and verifiable:

- Test wallet export paths with non-secret testnet, signet, or regtest fixtures.
- Review the safety model, threat model, descriptor audit, and scoring logic.
- Improve recovery runbooks so a real person can follow them under stress.
- Add deterministic fixtures for wallet coordinators and descriptor formats.
- Help shape Bitcoin Recovery Day: a recurring community drill for people who
  hold their own keys.

Do not contribute real wallet data. That means no real descriptors, xpubs,
addresses, seed words, private keys, passphrases, signer locations, logs, or
wallet metadata.

## Configuration

Deployment-specific values such as GitHub org, domain, and maintainer PGP key
live in `project.config.toml`. Some release-signing values still ship as
placeholders during pre-alpha. See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
for what each value means and how to replace it.

## License

Code is licensed under the [MIT License](LICENSE). Documentation under `docs/`
is licensed CC-BY-SA-4.0. Contributions are accepted under the Developer
Certificate of Origin (DCO). Sign commits with `git commit -s`. There is no CLA.
