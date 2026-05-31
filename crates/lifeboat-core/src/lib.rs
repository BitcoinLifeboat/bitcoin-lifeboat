//! `lifeboat-core` — the public API façade for Bitcoin Lifeboat.
//!
//! This crate is a thin re-export layer: it carries **no business logic of its
//! own** and simply re-exports the stable public API of every core analysis
//! crate so that the CLI (`cli/lifeboat`, US-035+) and the Tauri desktop app
//! (US-041+) build against one identical surface. A consumer depends only on
//! `lifeboat-core` and reaches any core item through it — e.g.
//! [`descriptor_audit::parse_descriptor`] is available as
//! `lifeboat_core::descriptor_audit::parse_descriptor`. The crate names are kept
//! verbatim so a path that works against a core crate directly works unchanged
//! through the façade.
//!
//! # Dependency graph (PRD §20)
//!
//! ```text
//! lifeboat-core (this crate — façade, no logic)
//! ├── descriptor-audit          # parsing, normalization, analysis
//! ├── address-derive            # address generation + verification
//! ├── readiness-score           # scoring engine
//! ├── sensitive-input-detector  # secret detection
//! ├── wallet-imports            # multi-wallet import normalizer
//! ├── psbt-tools                # PSBT file import and inspection
//! ├── qr-psbt                   # UR QR PSBT transport
//! ├── miniscript-viz            # policy-to-DOT visualization
//! ├── report-engine             # JSON + Markdown reports
//! ├── error-taxonomy            # typed error codes
//! └── runbook-engine            # PDF / Markdown runbooks (Typst)
//! ```
//!
//! The core crates themselves form a layered graph — each layer depends only on
//! the ones above it (arrows below point at the dependency):
//!
//! - **`error-taxonomy`** — the foundation. The single typed error vocabulary
//!   ([`error_taxonomy::LifeboatError`] over [`error_taxonomy::ErrorCode`]);
//!   depends on no other workspace crate.
//! - **`descriptor-audit`** → `error-taxonomy`. Parses and analyzes output
//!   descriptors ([`descriptor_audit::parse_descriptor`] yields a
//!   [`descriptor_audit::ParsedDescriptor`]).
//! - **`sensitive-input-detector`** → `error-taxonomy`. Screens pasted input for
//!   secret material without ever echoing it ([`sensitive_input_detector::detect`]).
//! - **`address-derive`** → `descriptor-audit`, `error-taxonomy`. Derives and
//!   compares addresses off a [`descriptor_audit::ParsedDescriptor`].
//! - **`wallet-imports`** → `descriptor-audit`, `error-taxonomy`. Normalizes the
//!   supported wallets' exports into one shape.
//! - **`psbt-tools`** → `error-taxonomy`. Imports and inspects PSBT files for the
//!   root CLI without BDK or wallet state.
//! - **`qr-psbt`** → `error-taxonomy`, `ur`. Encodes and decodes PSBTs as
//!   BCR-2020-005/006 UR frames for QR exchange.
//! - **`miniscript-viz`** → `descriptor-audit`, `error-taxonomy`,
//!   `miniscript`. Lifts descriptor spending policies and emits redacted
//!   GraphViz DOT for UI visualization.
//! - **`readiness-score`** → `descriptor-audit`, `address-derive`,
//!   `error-taxonomy`. The §9/§16 checks, criticals, score, status, and
//!   survivability.
//! - **`report-engine`** → `readiness-score`, `address-derive`,
//!   `descriptor-audit`. Orchestrates the lower layers into the deterministic
//!   §19.1 [`report_engine::ReadinessReport`] (JSON + Markdown).
//! - **`runbook-engine`** → `report-engine`, `error-taxonomy`. Renders the
//!   printable owner/heir recovery runbooks (PDF + Markdown).
//!
//! # No GUI dependency (PRD §13.7 / §20)
//!
//! All Bitcoin logic lives in these GUI-agnostic Rust crates. None of them — and
//! not this façade — may depend on `tauri` or any other UI framework; only the
//! desktop-app crate (US-041) links the GUI. The architecture guard in
//! `tests/no_tauri.rs` fails the build if any core crate gains a Tauri
//! dependency.

/// Typed error vocabulary: [`LifeboatError`](error_taxonomy::LifeboatError),
/// [`ErrorCode`](error_taxonomy::ErrorCode), and
/// [`Severity`](error_taxonomy::Severity).
pub use error_taxonomy;

/// Output-descriptor parsing, normalization, and analysis:
/// [`parse_descriptor`](descriptor_audit::parse_descriptor) yields a
/// [`ParsedDescriptor`](descriptor_audit::ParsedDescriptor).
pub use descriptor_audit;

/// Address derivation and known-address comparison
/// ([`derive_addresses`](address_derive::derive_addresses)).
pub use address_derive;

/// Sensitive-input (secret) detection
/// ([`detect`](sensitive_input_detector::detect)) — the report carries only
/// discriminants and byte ranges, never the secret content.
pub use sensitive_input_detector;

/// The §9/§16 readiness checks, criticals, scoring, status, and survivability
/// ([`run_checks`](readiness_score::run_checks),
/// [`compute_score`](readiness_score::compute_score)).
pub use readiness_score;

/// Multi-wallet export normalization into
/// [`NormalizedWalletExport`](wallet_imports::NormalizedWalletExport).
pub use wallet_imports;

/// PSBT import, inspection, and finalized-transaction extraction for the CLI.
pub use psbt_tools;

/// UR QR PSBT transport helpers for air-gapped exchange.
pub use qr_psbt;

/// Miniscript policy visualization helpers for GraphViz DOT output.
pub use miniscript_viz;

/// The deterministic §19.1 readiness report:
/// [`build_report`](report_engine::build_report) yields a
/// [`ReadinessReport`](report_engine::ReadinessReport) (JSON + Markdown).
pub use report_engine;

/// Printable recovery / inheritance runbooks (PDF via Typst, Markdown fallback).
pub use runbook_engine;
