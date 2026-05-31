//! Architecture guard (US-034, PRD §13.7 / §20): no core crate — and not the
//! `lifeboat-core` façade — may depend on Tauri or any other GUI framework. All
//! Bitcoin logic lives in GUI-agnostic Rust; only the desktop-app crate (US-041)
//! is permitted to link Tauri.
//!
//! This is the workspace CI check required by US-034: it runs under
//! `cargo test --workspace` and reads each core crate's `Cargo.toml`, failing if
//! any of them declares a `tauri` dependency. Inspecting the manifests (rather
//! than the whole `Cargo.lock`) keeps the guard correct once US-041 adds the
//! desktop app, whose `tauri` dependency is legitimate and lives in a separate,
//! non-core crate.

use std::path::Path;

/// Every crate that must remain GUI-agnostic: the eight core crates of the PRD
/// §20 graph plus the `lifeboat-core` façade itself.
const CORE_CRATES: &[&str] = &[
    "error-taxonomy",
    "descriptor-audit",
    "address-derive",
    "sensitive-input-detector",
    "readiness-score",
    "wallet-imports",
    "qr-psbt",
    "miniscript-viz",
    "report-engine",
    "runbook-engine",
    "lifeboat-core",
];

/// True if a manifest declares a dependency on `tauri` (or any `tauri*` crate).
/// Full-line and inline `#` comments are stripped first, so a mention of Tauri in
/// prose does not trip the guard — only dependency-declaration text is inspected.
fn declares_tauri(manifest: &str) -> bool {
    manifest.lines().any(|line| {
        let code = line.split('#').next().unwrap_or("").trim();
        // `tauri = ...`, `tauri.workspace = true`, `tauri-build = ...`, and a
        // `[dependencies.tauri]` / `[build-dependencies.tauri]` table header.
        code.starts_with("tauri") || code.contains(".tauri]")
    })
}

#[test]
fn no_core_crate_depends_on_tauri() {
    // The workspace root is two levels above this crate's manifest dir
    // (`<root>/crates/lifeboat-core`).
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above the crate manifest dir");

    for crate_name in CORE_CRATES {
        let manifest_path = workspace_root
            .join("crates")
            .join(crate_name)
            .join("Cargo.toml");
        let manifest = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", manifest_path.display()));
        assert!(
            !declares_tauri(&manifest),
            "{crate_name}/Cargo.toml must not depend on tauri (PRD §13.7/§20: core \
             crates are GUI-agnostic; only the US-041 desktop app may link Tauri)"
        );
    }
}

#[test]
fn guard_detects_a_tauri_dependency() {
    // Self-check: the heuristic actually catches the forms a real Cargo.toml uses,
    // so the guard above cannot silently pass on a future regression.
    assert!(declares_tauri("tauri = \"2\""));
    assert!(declares_tauri("tauri.workspace = true"));
    assert!(declares_tauri("[dependencies.tauri]"));
    assert!(declares_tauri("tauri-build = { version = \"2\" }"));
    // ...and does not fire on prose or unrelated dependencies.
    assert!(!declares_tauri("# this crate is GUI-agnostic, never tauri"));
    assert!(!declares_tauri("descriptor-audit.workspace = true"));
    assert!(!declares_tauri("serde = { version = \"1\" } # not tauri"));
}
