# Architecture

Bitcoin Lifeboat is a local-first desktop app and CLI backed by Rust core crates.
The frontend renders screens and sends typed requests. Bitcoin logic stays in
Rust.

## Layers

```text
React desktop UI
  -> typed Tauri command wrappers
  -> thin src-tauri command functions
  -> desktop-commands crate
  -> core crates
  -> report/runbook/export artifacts
```

The CLI enters the same core crates through `lifeboat-core`. It does not parse
descriptors, derive addresses, detect secrets, or calculate scores itself.

## Core Rule

The frontend must never implement Bitcoin logic. That includes descriptor
parsing, BIP380 checksum validation, address derivation, sensitive-input
detection, scoring, report generation, PSBT logic, and cryptography. The
frontend is a presentation layer.

## Crate Responsibilities

| Crate | Responsibility |
| --- | --- |
| `lifeboat-core` | Facade that re-exports stable core APIs to the CLI and desktop command layer |
| `error-taxonomy` | Stable `E-*` error codes, metadata, i18n seed text, and leak-free error serialization |
| `sensitive-input-detector` | Shape-based detection for seed phrases, private keys, xprvs, raw private-key hex, SLIP-39, and codex32 |
| `descriptor-audit` | BIP380 descriptor parse, checksum, normalization, key origins, network inference, and descriptor facts |
| `address-derive` | Receive/change address derivation and known-address comparison |
| `readiness-score` | A-G checks, critical issues, warnings, status mapping, and survivability facts |
| `wallet-imports` | Wallet export parsing into `NormalizedWalletExport` |
| `report-engine` | Deterministic JSON and Markdown readiness reports with public-safe redaction |
| `runbook-engine` | Owner and heir runbook rendering in PDF, Markdown, text, and HTML |
| `desktop-commands` | GUI-agnostic command logic used by Tauri wrappers |

## Desktop App

The desktop app lives under `apps/desktop`. Its React code uses TypeScript,
Tailwind, i18next, Zustand, and HashRouter. Confidential values stay in local
screen state or the non-persisted session store. Public preferences persist only
through the Tauri-managed settings file.

`apps/desktop/src-tauri` is a detached Cargo workspace because the Tauri GUI tree
needs system libraries and a newer local Rust toolchain. Core crates remain on
the root Rust 1.78 toolchain.

## Tauri Command Surface

The MVP command surface includes:

- `audit_descriptor`
- `derive_addresses`
- `compare_address`
- `detect_sensitive_input`
- `parse_wallet_export`
- `validate_checksum`
- `compute_checksum`
- `generate_report`
- `generate_runbook`
- `save_export`
- `open_external_link`
- `get_app_info`
- settings commands added for desktop preferences

Inputs are validated at the boundary. Strings that may contain wallet data are
screened before parse/import. Errors cross the boundary as `LifeboatError`
metadata, not as raw library errors.

## Files, Links, and Network

The Tauri capability set is intentionally narrow: file dialogs, scoped file
read/write, OS info, and process exit. Lifeboat does not include the Tauri
updater, shell, HTTP, clipboard-manager, notification, global shortcut, or
webview-creation capabilities.

External links are allowlisted in Rust and opened by the operating system
browser. The webview does not navigate to arbitrary URLs.

## Tests

The core quality gate is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Desktop UI stories additionally run the app-level TypeScript, Vitest,
Playwright, and security guardrail scripts from `apps/desktop`.

## Related Docs

- [Safety model](safety-model.md)
- [Threat model](threat-model.md)
- [Descriptor audit](descriptor-audit.md)
- [Scoring](scoring.md)
- [CLI reference](cli-reference.md)
- [JSON schemas](json-schemas.md)

