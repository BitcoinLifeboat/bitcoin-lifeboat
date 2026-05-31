//! Build script for `desktop-commands` (US-043).
//!
//! Generates the `open_external_link` allowlist source values **at build time**
//! from the repo-root `project.config.toml` (the §30.6 single source of truth):
//! `github.url_base` and `site.domain`. They are exposed to the crate as the
//! `LIFEBOAT_GH_URL_BASE` / `LIFEBOAT_SITE_DOMAIN` compile-time environment
//! variables (read with `env!` in `lib.rs`), so changing the org or domain in
//! `project.config.toml` updates the external-link allowlist with **no code
//! change** (PRD §21.3). No `org`/`domain` is ever hardcoded in Rust.
//!
//! This script uses only `std` — no TOML crate — to avoid adding a dependency
//! (and its MSRV exposure) for reading two scalar values from a file the project
//! controls and keeps in a simple, stable shape.

use std::path::Path;

fn main() {
    // `project.config.toml` lives at the repo root, two levels up from this crate
    // (`crates/desktop-commands/` → repo root). `CARGO_MANIFEST_DIR` is this crate.
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is always set by Cargo for a build script");
    let config_path = Path::new(&manifest)
        .join("..")
        .join("..")
        .join("project.config.toml");

    let config = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        panic!(
            "US-043: cannot read project.config.toml at {} (the open_external_link \
             allowlist is generated from it): {e}",
            config_path.display()
        )
    });

    let url_base = toml_scalar(&config, "github", "url_base").unwrap_or_else(|| {
        panic!(
            "US-043: project.config.toml is missing `github.url_base`, required to \
             generate the external-link allowlist"
        )
    });
    let domain = toml_scalar(&config, "site", "domain").unwrap_or_else(|| {
        panic!(
            "US-043: project.config.toml is missing `site.domain`, required to \
             generate the external-link allowlist"
        )
    });

    println!("cargo:rustc-env=LIFEBOAT_GH_URL_BASE={url_base}");
    println!("cargo:rustc-env=LIFEBOAT_SITE_DOMAIN={domain}");
    // Rebuild whenever the config (or this script) changes, so the allowlist tracks
    // the org/domain automatically.
    println!("cargo:rerun-if-changed={}", config_path.display());
    println!("cargo:rerun-if-changed=build.rs");
}

/// Extract a `key = "value"` double-quoted scalar under `[section]` from a
/// well-formed TOML document.
///
/// This is intentionally minimal — it handles exactly the shape
/// `project.config.toml` uses for these keys (a quoted scalar, optionally
/// followed by a `#` comment) and is **not** a general TOML parser (no arrays,
/// nesting, or multi-line strings). Returns `None` if the section or key is
/// absent.
fn toml_scalar(toml: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in toml.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A `[section]` header switches which table we are in.
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = header.trim() == section;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() != key {
                continue;
            }
            // Take the contents between the first pair of double quotes, which
            // discards any trailing inline `# comment`.
            let after_open = v.trim().strip_prefix('"')?;
            let end = after_open.find('"')?;
            return Some(after_open[..end].to_owned());
        }
    }
    None
}
