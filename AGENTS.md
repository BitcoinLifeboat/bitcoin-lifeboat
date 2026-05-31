# Repository Guidelines

## Project Structure & Module Organization

Bitcoin Lifeboat is a Rust-first workspace. Core logic lives in `crates/`, with the
main CLI in `cli/lifeboat`. Shared fixtures are under `fixtures/`, documentation is
under `docs/`, and release/security checks live in `scripts/`. The desktop UI and
docs site are detached Node workspaces under `apps/desktop` and `apps/docs-site`.
Fuzz targets are in the detached `fuzz/` workspace. Check nearby `CLAUDE.md` files
before editing a module; they document local invariants.

## Build, Test, and Development Commands

- `cargo build --workspace`: build the core Rust workspace.
- `cargo test --workspace`: run Rust unit and snapshot tests.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: run the CI lint gate.
- `cargo build -p lifeboat --release`: build the CLI binary.
- `cd apps/desktop && npm ci && npm run build`: build the desktop frontend.
- `cd apps/desktop && npm test`: run frontend guardrail and Vitest tests.
- `cd apps/docs-site && npm ci && npm run build`: build the public docs site.

The root toolchain is pinned to Rust 1.78 via `rust-toolchain.toml`; Node is pinned
by `.nvmrc`.

## Coding Style & Naming Conventions

Use Rust 2021, four-space indentation, Unix newlines, and `rustfmt.toml` settings.
Keep Bitcoin parsing, derivation, scoring, secret detection, and crypto in Rust
core crates. UI and CLI layers should call typed crate APIs instead of duplicating
domain logic. Avoid `unwrap()` and `panic!()` outside tests. Use typed errors from
`error-taxonomy`; do not add ad hoc user-facing error strings.

## Testing Guidelines

Put Rust tests near the code they cover. CLI golden output uses `insta` snapshots
under `cli/lifeboat/src/snapshots/`; regenerate intentionally with
`INSTA_UPDATE=always cargo +1.78.0 test -p lifeboat`. Frontend tests use Vitest and
Playwright from `apps/desktop`. Never commit real wallet data; use deterministic
testnet, signet, or regtest fixtures only.

## Commit & Pull Request Guidelines

History uses `feat: [US-###] - summary` style for story work. This project uses
DCO sign-off, so commit with `git commit -s`. Pull requests should include a short
summary, linked story/issue/PRD section, exact checks run, screenshots or notes for
UI changes, and any security, privacy, or deterministic-output impact.

## Security & Configuration Tips

Do not add telemetry, auto-update, analytics, network behavior, or broader Tauri
capabilities without a PRD-backed story. Do not commit real descriptors, xpubs,
addresses, seed words, private keys, passphrases, signer locations, logs, or
wallet metadata. Deployment placeholders live in `project.config.toml`; see
`docs/CONFIGURATION.md` before changing them.
