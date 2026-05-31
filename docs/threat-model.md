# Threat Model

This document summarizes the threats tracked for the MVP and how Lifeboat
responds. It does not claim to remove every risk. It states what is handled,
what is reduced, and what remains outside the product boundary.

## Trust Boundaries

The user trusts Lifeboat with watch-only wallet metadata, the name of the wallet
software they use, and known receive addresses. The user does not trust Lifeboat
with seed phrases, private keys, passphrases, custody of funds, or automatic
network contact with wallet metadata.

The user still has to trust the release artifact, their operating system, the
webview, and the Bitcoin Rust libraries used for descriptor parsing and address
derivation.

## Threats T1-T20

| ID | Threat | Lifeboat response | Residual risk |
| --- | --- | --- | --- |
| T1 | Phishing site impersonates Lifeboat | Docs tell users to use official release channels; the project publishes official URLs and security contact details | Users can still be tricked by look-alike domains |
| T2 | Malicious build or supply-chain compromise | Pinned dependencies, signed releases, cargo/npm checks, and a reproducible-build roadmap | Full deterministic installers are a v1.0 target |
| T3 | Clipboard leakage | Lifeboat never auto-reads the clipboard; pasted content is screened before processing | Clipboard managers or the OS may retain data |
| T4 | Accidental seed phrase paste | Sensitive-input detector blocks seed-like input and clears the field | Webview memory cannot be perfectly wiped |
| T5 | Compromised npm or cargo dependency | Lockfiles, dependency review, cargo-deny, audit checks, and two-maintainer review for sensitive areas | Any dependency tree has ongoing maintenance risk |
| T6 | Malicious update server | No auto-updater; users manually fetch releases | Users may download from the wrong place |
| T7 | Hardware wallet spoofing | MVP does not claim device-authentication coverage; v0.4 plans fingerprint verification | File-based MVP flows cannot prove device identity |
| T8 | User confuses testnet, Signet, regtest, and mainnet | Network banners and explicit overrides for ambiguous tpub descriptors | The user can still choose the wrong network |
| T9 | Heir exposes real secrets in a drill | Heir runbooks use instructions and blanks; Lifeboat does not collect seed words or passphrases | A printed owner-created packet can still be mishandled |
| T10 | False confidence from an incomplete drill | Reports list untested scenarios and include mandatory disclaimers | A user may ignore missing checks |
| T11 | Webview remote code execution through XSS | Strict CSP, no remote docs fetch, no eval, and a narrow Tauri capability set | Webview engine bugs can still exist |
| T12 | Memory disclosure through paging or process inspection | Secret types are zeroized in Rust, and webview limits are documented | The browser engine cannot provide perfect memory erasure |
| T13 | Coerced disclosure | Documented as out of scope | Physical coercion needs non-software planning |
| T14 | Forensic recovery of files on disk | No default persistence for descriptors, reports, or runbooks; logs off by default | User-exported files may remain recoverable on disk |
| T15 | Updater key compromise | No updater plugin is shipped | Manual update habits still matter |
| T16 | Code-signing certificate theft | Signing keys are planned for CI/HSM-backed services with revocation procedures | Stolen signing authority may still require public revocation response |
| T17 | Maintainer account takeover | Protected branches, signed commits, and two-maintainer review for sensitive changes | Account recovery and hosting-provider risk remain |
| T18 | Tauri webview CVE | Tauri and OS webviews are pinned and updated through releases; stale builds get advisories | Users must keep their OS and app version current |
| T19 | Malicious wallet export file | Rust parsers reject large files, use strict formats where possible, and never execute file content | Parser bugs remain possible and are covered by tests/fuzzing |
| T20 | Side-channel from logs | Logs are off by default and must scrub Confidential fields | Local diagnostic files can still reveal timing or workflow facts |

## Reporting a Security Issue

Use the project security contact from `project.config.toml` or the published
security policy. Do not include seed phrases, private keys, passphrases, or full
wallet descriptors in an issue. If reproduction needs a descriptor, use the
test fixtures under `fixtures/` or a newly generated testnet descriptor.

