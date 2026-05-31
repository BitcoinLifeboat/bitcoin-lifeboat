# v0.1 MVP Acceptance Verification

This page maps the PRD §27 MVP acceptance gate to concrete repository evidence:
tests, fixtures, docs, workflows, or generated release artifacts. The canonical
acceptance list remains [PRD-v2.md](PRD-v2.md#27-acceptance-criteria-for-mvp).

## Verification Gate

Run this gate before cutting a v0.1 release candidate:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cd apps/desktop && npm run typecheck && npm test && npm run build && npm run verify:security && npm run e2e && npm run e2e:no-network
cd apps/docs-site && npm run typecheck && npm run build
```

For a native desktop release candidate, also verify the platform prerequisites
and the bundled HWI sidecar before invoking Tauri:

```sh
scripts/check-native-desktop-deps.sh
scripts/install-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
scripts/verify-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
cd apps/desktop/src-tauri && cargo test
```

Stable public releases additionally require
`docs/security-audit-signoff.json` and
`docs/hardware-wallet-device-matrix.json`; the release gate rejects a stable tag
until both are complete:

```sh
scripts/verify-release-gates.sh --tag v1.0.0
```

CI adds the cross-OS Rust/Node matrix, coverage enforcement, supply-chain scans,
bounded fuzzing, and release-artifact signing:

- `.github/workflows/ci.yml`: Rust build/fmt/clippy/test, desktop typecheck/test/build/security, and per-crate Rust coverage at 80% or higher.
- `.github/workflows/docs.yml`: Starlight docs build and GitHub Pages deploy.
- `.github/workflows/security.yml`: cargo-audit, cargo-deny, npm audit, OSV reporting, gitleaks, and Semgrep.
- `.github/workflows/fuzz.yml`: all fuzz targets with a 5 minute PR/push bound.
- `.github/workflows/release.yml`: signed desktop installers, signed CLI archives, checksums, SBOMs, release notes, and SLSA provenance.

## Functional Acceptance

| # | Criterion | Evidence |
|---|---|---|
| 1 | Signed installers are published for macOS, Windows, and Linux. | `.github/workflows/release.yml` desktop matrix builds macOS DMG, Windows MSI, Linux AppImage/deb, then the publish job signs and uploads them. |
| 2 | The app launches on each supported OS. | `.github/workflows/ci.yml` runs the frontend build/test matrix across macOS, Windows, and Ubuntu; `.github/workflows/release.yml` builds the native Tauri bundles per OS. |
| 3 | A valid singlesig descriptor produces a Readiness Report. | `crates/desktop-commands/tests/commands.rs` covers `audit_descriptor`; `fixtures/descriptors/singlesig/*.txt` provide valid inputs; `apps/desktop/src/pages/ReadinessWizard.test.tsx` and `apps/desktop/e2e/readiness-and-heir.spec.ts` cover the UI flow. |
| 4 | A valid 2-of-3 multisig descriptor reports threshold and key count. | `crates/descriptor-audit/src/lib.rs`, `crates/readiness-score/src/lib.rs`, and `crates/desktop-commands/tests/commands.rs` cover multisig facts; `fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt` is the fixture. |
| 5 | BIP39 mnemonic paste is blocked for all supported languages. | `crates/sensitive-input-detector/src/mnemonic.rs` loads all BIP39 wordlists and tests valid/possible mnemonics; desktop screening is covered in `ReadinessWizard.test.tsx`. |
| 6 | WIF private key paste is blocked. | `crates/sensitive-input-detector/src/wif.rs` and `fixtures/secrets/wif_mainnet.txt`; `crates/desktop-commands/tests/commands.rs` verifies detector output contains no secret material. |
| 7 | xprv paste is blocked. | `crates/sensitive-input-detector/src/xprv.rs`, `crates/descriptor-audit/src/lib.rs`, and `fixtures/secrets/xprv_mainnet.txt`; CLI and desktop command tests block xprv before echoing input. |
| 8 | SLIP-39 share paste is blocked. | `crates/sensitive-input-detector/src/slip39.rs` and `fixtures/secrets/slip39_share_20w.txt`. |
| 9 | codex32 paste is blocked. | `crates/sensitive-input-detector/src/codex.rs` and `fixtures/secrets/codex32_128bit.txt`. |
| 10 | BIP380 checksum is validated when present. | `crates/descriptor-audit/src/lib.rs`, `crates/desktop-commands/tests/commands.rs`, and `cli/lifeboat/src/commands.rs` cover valid, missing, and invalid checksum paths. |
| 11 | A missing descriptor checksum can be computed after user action. | Core computation is `descriptor_audit::compute_checksum`; desktop/Tauri command exposure is `compute_checksum`; CLI coverage is `lifeboat checksum --compute`. |
| 12 | First 10 receive and change addresses derive correctly. | `crates/address-derive/src/lib.rs` and `crates/desktop-commands/tests/commands.rs` cover receive/change derivation and published vectors. |
| 13 | Known-address comparison reports hit/miss with derivation index. | `crates/address-derive/src/lib.rs`, `crates/readiness-score/src/lib.rs`, `crates/desktop-commands/tests/commands.rs`, and `fixtures/addresses/*.txt`. |
| 14 | Qualitative status and numeric score are generated per §16. | `crates/readiness-score/src/lib.rs` maps checks to score/status; report snapshots and golden corpus pin the output. |
| 15 | Critical issues, warnings, and passes are listed per §16.3-16.4. | `crates/readiness-score/src/lib.rs` defines critical/warning/pass codes; `crates/report-engine/src/lib.rs` renders them; `fixtures/reports/*.json` cover scenarios. |
| 16 | Markdown report includes all §15.10 sections. | `crates/report-engine/src/lib.rs` and its insta snapshots cover Markdown rendering, including the required "cannot tell you" section. |
| 17 | JSON report conforms to the §19.1 schema. | `crates/report-engine/tests/golden_corpus.rs`, `fixtures/reports/*.json`, and [JSON schemas](json-schemas.md). |
| 18 | singlesig-basic PDF runbook generates under 3 seconds. | `crates/runbook-engine/src/lib.rs` renders PDF through the deterministic backend; `crates/runbook-engine/src/snapshots/*pdf_sha256.snap` pins the binary output hash. |
| 19 | Public-safe and private export modes are offered. | `crates/report-engine/src/lib.rs`, `crates/runbook-engine/src/lib.rs`, `apps/desktop/src/components/ExportPrivacyDialog.test.tsx`, and wizard/runbook page tests cover both modes and the confirmation gate. |
| 20 | CLI implements the eight MVP commands. | `cli/lifeboat/src/cli.rs` defines `audit-descriptor`, `derive-addresses`, `compare-address`, `generate-runbook`, `report-json`, `detect-secrets`, `parse-export`, and `checksum`; parser and handler tests cover them. |
| 21 | Unit tests pass for all crates with at least 80% coverage. | `cargo test --workspace --all-targets`; `.github/workflows/ci.yml` runs `cargo llvm-cov` and `scripts/check-rust-coverage.py target/llvm-cov.json 80`. |
| 22 | Integration tests pass for Tier-1 wallet importers. | `crates/wallet-imports` tests use fixtures under `fixtures/wallet_exports/`; [Wallet compatibility](wallet-compatibility.md) documents Tier-1 and Tier-2 support. |
| 23 | Snapshot tests pass for at least 50 fixture descriptors. | `crates/report-engine/tests/golden_corpus.rs` covers the `fixtures/reports/` corpus, currently 50+ JSON report fixtures. |
| 24 | Fuzz targets run 5 minutes per PR without panics. | `.github/workflows/fuzz.yml` runs `fuzz_detector_arbitrary`, `fuzz_detector_false_positive`, `fuzz_detector_false_negative`, and `fuzz_descriptor_with_xprv` with `FUZZ_MAX_TOTAL_TIME=300`. |
| 25 | No-network-egress test passes. | `apps/desktop/scripts/no-network-egress.mjs` runs Playwright in a network namespace and `apps/desktop/e2e/support/tauri.ts` blocks all non-loopback browser requests. |
| 26 | axe-core reports zero WCAG AA violations. | `apps/desktop/src/a11y.test.tsx`, `apps/desktop/src/test/axe.ts`, and Playwright `expectNoAxeViolations` run WCAG 2.0/2.1/2.2 A/AA checks. |

## Documentation Acceptance

| # | Criterion | Evidence |
|---|---|---|
| 27 | README explains the product, non-goals, four promises, install instructions, and docs link. | Root `README.md`; `crates/error-taxonomy/tests/governance.rs` checks the promises and configured links. |
| 28 | SECURITY.md includes PGP key, disclosure address, and 90-day window. | Root `SECURITY.md`; `crates/error-taxonomy/tests/governance.rs` checks config-derived security contact and PGP placeholder/real-key behavior. |
| 29 | Threat model covers T1-T20 from §13.3. | [Threat model](threat-model.md). |
| 30 | CLI reference is generated from clap and reviewed. | [CLI reference](cli-reference.md); `cli/lifeboat/src/commands.rs` has `completions` and `man` generation paths. |
| 31 | JSON schemas are documented. | [JSON schemas](json-schemas.md). |
| 32 | Error codes are documented. | [Error codes](error-codes.md); `crates/error-taxonomy/tests/docs.rs` checks every `ErrorCode::ALL` entry appears. |
| 33 | Wallet compatibility covers all Tier-1 and Tier-2 wallets with export instructions. | [Wallet compatibility](wallet-compatibility.md) and `fixtures/wallet_exports/`. |
| 34 | Reproducible builds doc explains current and target state. | [Reproducible builds](reproducible-builds.md). |
| 35 | Docs tell users not to enter real seed phrases. | [Safety model](safety-model.md), [User guide](user-guide.md), and [Download and verify signatures](download-verify-signature.md). |
| 36 | Every report includes "What this report cannot tell you". | `crates/report-engine/src/lib.rs`, report snapshots, and desktop report viewer tests. |

## Release Acceptance

| # | Criterion | Evidence |
|---|---|---|
| 37 | GitHub Release contains signed installers, signed CLI binaries, checksums, SBOM, source tarball, and release notes. | `.github/workflows/release.yml` `desktop`, `cli`, `source-and-sbom`, and `publish` jobs collect and upload those artifacts. |
| 38 | minisign signatures verify against the published public key. | `.github/workflows/release.yml` `Minisign release artifacts` signs every artifact and immediately verifies with `MINISIGN_PUBLIC_KEY`. |
| 39 | cosign attestations exist for build provenance. | `.github/workflows/release.yml` signs blobs with cosign bundles, then invokes SLSA L3 provenance generation. |
| 40 | Two-maintainer approval is recorded in release dispatch logs. | `.github/workflows/release.yml` publish job uses the protected `release-two-maintainer` GitHub Environment. |

## Anti-Acceptance Verification

| # | Forbidden item | Evidence of absence |
|---|---|---|
| 41 | Frontend Bitcoin/crypto libraries. | `apps/desktop/scripts/verify-frontend-guardrails.mjs` scans package dependencies and imports for forbidden crypto/Bitcoin modules; `npm run verify:guardrails` and `npm test` run it. |
| 42 | Web-storage writes for Confidential data. | The same guardrail scanner fails on `localStorage.setItem` / `sessionStorage.setItem`; `apps/desktop/src/store/session.test.ts` asserts Confidential session state never persists. |
| 43 | Outbound network calls during E2E. | `npm run e2e:no-network` uses Linux network isolation plus the Playwright route guard in `apps/desktop/e2e/support/tauri.ts`. |
| 44 | Positive funds-safety overclaim copy. | `verify-frontend-guardrails.mjs` fails on positive wallet/funds/recovery overclaim patterns; `crates/report-engine/src/lib.rs` also lints report text. Negated disclaimers remain allowed. |
| 45 | Advanced seed-entry mode outside Practice Mode. | `apps/desktop/src/pages/Settings.tsx` exposes no seed-entry bypass; detector-first flows in the Readiness, Runbook, and Heir screens block real secrets before processing. |
| 46 | Analytics SDK or tracking snippet. | `verify-frontend-guardrails.mjs` scans dependencies, imports, and common analytics calls; `.github/workflows/security.yml` also audits npm dependency trees. |
| 47 | Tauri auto-updater plugin or config. | `apps/desktop/scripts/verify-capabilities.mjs` checks `tauri.conf.json` and `src-tauri/Cargo.toml`; `verify-frontend-guardrails.mjs` checks frontend updater deps/config. |
| 48 | Dynamic JavaScript code execution. | `verify-frontend-guardrails.mjs` fails on `eval`, `Function`, and string timers in frontend and E2E sources. |
